package com.ucas.infocollect.engine.sensor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import java.util.Random;

/**
 * SignalProcessingMath 的纯 JVM 单元测试。
 *
 * 重点验证两条不变量：
 *   1) 同一组样本两次哈希必须完全一致（去除浮点尾噪后的"确定性"指纹）；
 *   2) 不同器件噪声量级 σ（差异 ≥ 量化分辨率）必须产生不同哈希
 *      （即指纹对硬件个体敏感）。
 *
 * 同时覆盖 stripGravity / Rodrigues 旋转 / 距离判定 / 相似度衰减。
 */
public class SignalProcessingMathTest {

    private static final float G = 9.80665f;

    /** 生成"静止 + 高斯噪声"的合成加速度交错样本，重力沿 +z。 */
    private static float[] makeStaticAccel(int n, double sigma, long seed) {
        Random rng = new Random(seed);
        float[] out = new float[n * 3];
        for (int i = 0; i < n; i++) {
            out[i * 3]     = (float) (rng.nextGaussian() * sigma);
            out[i * 3 + 1] = (float) (rng.nextGaussian() * sigma);
            out[i * 3 + 2] = G + (float) (rng.nextGaussian() * sigma);
        }
        return out;
    }

    /** 生成"静止 + 偏置 + 噪声"的合成陀螺仪交错样本。 */
    private static float[] makeStaticGyro(int n, double bias, double sigma, long seed) {
        Random rng = new Random(seed);
        float[] out = new float[n * 3];
        for (int i = 0; i < n; i++) {
            out[i * 3]     = (float) (bias + rng.nextGaussian() * sigma);
            out[i * 3 + 1] = (float) (bias * 0.5 + rng.nextGaussian() * sigma);
            out[i * 3 + 2] = (float) (-bias * 0.3 + rng.nextGaussian() * sigma);
        }
        return out;
    }

    // ── 1) 同一组样本两次哈希一致 ────────────────────────────────────

    @Test
    public void hashIsDeterministicForIdenticalSamples() {
        Vector3 stdA = new Vector3(0.012f, 0.011f, 0.013f);
        Vector3 gMean = new Vector3(0.001f, -0.0005f, 0.0015f);

        String h1 = SignalProcessingMath.fingerprintHash(stdA, gMean);
        String h2 = SignalProcessingMath.fingerprintHash(stdA, gMean);

        assertEquals("同一特征必须给出同一哈希", h1, h2);
        assertEquals("哈希长度应为 16 hex 字符（8 字节）", 16, h1.length());
    }

    @Test
    public void hashIsRobustToSubBucketNoise() {
        // 0.0001 远小于量化分辨率 0.001，应被分桶吸收
        Vector3 stdA1 = new Vector3(0.012f, 0.011f, 0.013f);
        Vector3 stdA2 = new Vector3(0.0123f, 0.0114f, 0.0132f);
        Vector3 gMean = new Vector3(0.001f, -0.0005f, 0.0015f);

        String h1 = SignalProcessingMath.fingerprintHash(stdA1, gMean);
        String h2 = SignalProcessingMath.fingerprintHash(stdA2, gMean);

        assertEquals("亚分桶尾噪不应改变哈希", h1, h2);
    }

    // ── 2) 不同 σ 产生不同哈希 ──────────────────────────────────────

    @Test
    public void differentSigmaProducesDifferentHash() {
        // 真实"两个不同器件"用大尺度差异确保跨过分桶
        Vector3 stdLowNoise  = new Vector3(0.005f, 0.005f, 0.005f);  // 低噪声器件
        Vector3 stdHighNoise = new Vector3(0.030f, 0.028f, 0.032f);  // 高噪声器件
        Vector3 gMean = new Vector3(0.0f, 0.0f, 0.0f);

        String h1 = SignalProcessingMath.fingerprintHash(stdLowNoise, gMean);
        String h2 = SignalProcessingMath.fingerprintHash(stdHighNoise, gMean);

        assertNotEquals("不同噪声量级必须给出不同哈希", h1, h2);
    }

    @Test
    public void differentGyroBiasProducesDifferentHash() {
        Vector3 stdA = new Vector3(0.012f, 0.011f, 0.013f);
        Vector3 gA = new Vector3(0.001f, -0.0005f, 0.0015f);
        Vector3 gB = new Vector3(-0.005f, 0.003f, 0.000f);

        String h1 = SignalProcessingMath.fingerprintHash(stdA, gA);
        String h2 = SignalProcessingMath.fingerprintHash(stdA, gB);

        assertNotEquals("不同陀螺零漂必须给出不同哈希", h1, h2);
    }

    @Test
    public void endToEndStaticSampleHashStable() {
        // 端到端：相同合成样本在重新跑一遍后给出相同哈希
        float[] a1 = makeStaticAccel(500, 0.012, 42L);
        float[] a2 = makeStaticAccel(500, 0.012, 42L);  // 同 seed 完全一致
        float[] g1 = makeStaticGyro(500, 0.001, 0.0005, 99L);
        float[] g2 = makeStaticGyro(500, 0.001, 0.0005, 99L);

        Vector3 m1 = SignalProcessingMath.meanXYZ(a1, 500);
        Vector3 s1 = SignalProcessingMath.stdDevXYZ(a1, 500, m1);
        Vector3 m2 = SignalProcessingMath.meanXYZ(a2, 500);
        Vector3 s2 = SignalProcessingMath.stdDevXYZ(a2, 500, m2);
        Vector3 gm1 = SignalProcessingMath.meanXYZ(g1, 500);
        Vector3 gm2 = SignalProcessingMath.meanXYZ(g2, 500);

        String h1 = SignalProcessingMath.fingerprintHash(s1, gm1);
        String h2 = SignalProcessingMath.fingerprintHash(s2, gm2);

        assertEquals("同种子同算法→同哈希", h1, h2);
    }

    @Test
    public void endToEndDifferentNoiseLevelDifferentHash() {
        // 端到端：两台器件噪声差一个数量级，必须产生不同哈希
        float[] aLow  = makeStaticAccel(500, 0.005, 1L);
        float[] aHigh = makeStaticAccel(500, 0.030, 1L);
        float[] g     = makeStaticGyro(500, 0.001, 0.0005, 1L);

        Vector3 mLow  = SignalProcessingMath.meanXYZ(aLow, 500);
        Vector3 sLow  = SignalProcessingMath.stdDevXYZ(aLow, 500, mLow);
        Vector3 mHigh = SignalProcessingMath.meanXYZ(aHigh, 500);
        Vector3 sHigh = SignalProcessingMath.stdDevXYZ(aHigh, 500, mHigh);
        Vector3 gMean = SignalProcessingMath.meanXYZ(g, 500);

        String hLow  = SignalProcessingMath.fingerprintHash(sLow,  gMean);
        String hHigh = SignalProcessingMath.fingerprintHash(sHigh, gMean);

        assertNotEquals("噪声尺度差异 → 哈希不同", hLow, hHigh);
    }

    // ── stripGravity ────────────────────────────────────────────────

    @Test
    public void stripGravityRemovesOneG() {
        Vector3 mean = new Vector3(0f, 0f, G);
        Vector3 res = SignalProcessingMath.stripGravity(mean);
        assertEquals(0f, res.x, 1e-6);
        assertEquals(0f, res.y, 1e-6);
        assertEquals(0f, res.z, 1e-4);
    }

    @Test
    public void stripGravityKeepsXYBias() {
        Vector3 mean = new Vector3(0.05f, -0.03f, G);
        Vector3 res = SignalProcessingMath.stripGravity(mean);
        assertEquals(0.05f, res.x, 1e-6);
        assertEquals(-0.03f, res.y, 1e-6);
    }

    // ── 旋转 ─────────────────────────────────────────────────────────

    @Test
    public void rotationFromToMapsVectorToTarget() {
        // (0,0,1) → (0,0,-1) 触发反向退化分支
        float[] R = SignalProcessingMath.rotationFromTo(
                new Vector3(0f, 0f, 1f), new Vector3(0f, 0f, -1f));
        Vector3 rotated = SignalProcessingMath.rotate(new Vector3(0f, 0f, 1f), R);
        assertEquals(0f, rotated.x, 1e-5);
        assertEquals(0f, rotated.y, 1e-5);
        assertEquals(-1f, rotated.z, 1e-5);
    }

    @Test
    public void rotationFromToHandlesArbitraryDirection() {
        Vector3 from = new Vector3(0.5f, 0.3f, 0.81f);  // 任意方向
        Vector3 to   = new Vector3(0f, 0f, -1f);
        float[] R = SignalProcessingMath.rotationFromTo(from, to);
        Vector3 rotated = SignalProcessingMath.rotate(from, R);
        // 旋转后应平行于 (0,0,-1)，模长 = |from|
        float fromLen = from.magnitude();
        assertEquals(0f, rotated.x, 1e-5);
        assertEquals(0f, rotated.y, 1e-5);
        assertEquals(-fromLen, rotated.z, 1e-5);
    }

    @Test
    public void rotationPreservesNorm() {
        Vector3 from = new Vector3(0.7f, -0.2f, 0.8f);
        Vector3 to   = new Vector3(0f, 0f, -1f);
        float[] R = SignalProcessingMath.rotationFromTo(from, to);

        Vector3 v = new Vector3(1.0f, 2.0f, 3.0f);
        Vector3 rv = SignalProcessingMath.rotate(v, R);
        assertEquals("旋转必须保持模长", v.magnitude(), rv.magnitude(), 1e-5);
    }

    @Test
    public void rotateInterleavedConsistentWithRotateOne() {
        Vector3 from = new Vector3(0.1f, 0.2f, 0.97f);
        Vector3 to   = new Vector3(0f, 0f, -1f);
        float[] R = SignalProcessingMath.rotationFromTo(from, to);

        float[] in = { 1f, 2f, 3f, -1f, 0.5f, 4f };
        float[] out = new float[6];
        SignalProcessingMath.rotateInterleaved(in, 2, R, out);

        Vector3 a = SignalProcessingMath.rotate(new Vector3(1f, 2f, 3f), R);
        Vector3 b = SignalProcessingMath.rotate(new Vector3(-1f, 0.5f, 4f), R);
        assertEquals(a.x, out[0], 1e-5);
        assertEquals(a.y, out[1], 1e-5);
        assertEquals(a.z, out[2], 1e-5);
        assertEquals(b.x, out[3], 1e-5);
        assertEquals(b.y, out[4], 1e-5);
        assertEquals(b.z, out[5], 1e-5);
    }

    // ── 相似度 / 判定 ─────────────────────────────────────────────

    @Test
    public void similarityMonotonicallyDecaysWithDistance() {
        double sigma = SignalProcessingMath.SIMILARITY_SIGMA;
        double s0 = SignalProcessingMath.similarityPercent(0.0,    sigma);
        double s1 = SignalProcessingMath.similarityPercent(0.001,  sigma);
        double s2 = SignalProcessingMath.similarityPercent(0.005,  sigma);
        double s3 = SignalProcessingMath.similarityPercent(0.02,   sigma);

        assertEquals(100.0, s0, 1e-9);
        assertTrue("0.001 距离应 ≈ 95%", s1 > 90.0 && s1 < 100.0);
        assertTrue("0.005 距离应 ≈ 78%", s2 > 70.0 && s2 < 85.0);
        assertTrue("σ 距离应 ≈ 36.8%",   s3 > 30.0 && s3 < 45.0);
        assertTrue("距离越大相似度越低", s0 > s1 && s1 > s2 && s2 > s3);
    }

    @Test
    public void classifyMatchThresholds() {
        assertEquals(SignalProcessingMath.MatchLevel.MATCH,
                SignalProcessingMath.classifyMatch(0.005));
        assertEquals(SignalProcessingMath.MatchLevel.LIKELY,
                SignalProcessingMath.classifyMatch(0.03));
        assertEquals(SignalProcessingMath.MatchLevel.UNLIKELY,
                SignalProcessingMath.classifyMatch(0.10));
        assertEquals(SignalProcessingMath.MatchLevel.NEW,
                SignalProcessingMath.classifyMatch(0.50));
        assertEquals(SignalProcessingMath.MatchLevel.NEW,
                SignalProcessingMath.classifyMatch(Double.NaN));
    }

    // ── 数学保留向后兼容 ────────────────────────────────────────────

    @Test
    public void meanAndVarianceUnchangedByRefactor() {
        float[] s = { 1f, 2f, 3f, 2f, 4f, 6f, 3f, 6f, 9f };
        Vector3 m = SignalProcessingMath.meanXYZ(s, 3);
        assertEquals(2f, m.x, 1e-6);
        assertEquals(4f, m.y, 1e-6);
        assertEquals(6f, m.z, 1e-6);

        Vector3 v = SignalProcessingMath.varianceXYZ(s, 3, m);
        // 总体方差：分母为 n
        assertEquals(2.0/3.0, v.x, 1e-6);
        assertEquals(8.0/3.0, v.y, 1e-6);
        assertEquals(6.0,     v.z, 1e-6);
    }

    @Test
    public void bytesToHexWorks() {
        byte[] in = { (byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF };
        assertEquals("DEADBEEF", SignalProcessingMath.bytesToHex(in, 0, 4));
        assertEquals("ADBE",     SignalProcessingMath.bytesToHex(in, 1, 2));
    }

    @Test
    public void fingerprintHashIsHexUppercase() {
        String h = SignalProcessingMath.fingerprintHash(
                new Vector3(0.01f, 0.01f, 0.01f), Vector3.ZERO);
        assertNotNull(h);
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            assertTrue("哈希必须是大写十六进制：" + c,
                    (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
        }
    }
}
