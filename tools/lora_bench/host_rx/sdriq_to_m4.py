"""Turn a 2 MS/s .sdriq capture into the int8 stream the PortaPack's M4 receives: frequency
shifted so MAIN_HZ sits at +500 kHz (the receiver tunes fs/4 below the channel), quantised to
int8. Optional extra MeshCore packets can be injected the way tools/dual_mix_test.py does.

  py sdriq_to_m4.py IN.sdriq OUT.cs8 MAIN_HZ [--scale S] [--noise RMS] [--seconds T]
                   [--add BURST.sdriq:T0:SNR_DB ...]

--add mixes a burst recorded/synthesised elsewhere (e.g. meshchat --net mc --encode-file) into
the capture at T0 seconds, at SNR_DB over the capture's own noise in a 62.5 kHz channel at the
burst's frequency - the way a weak MeshCore node would arrive on top of real receiver noise.
"""
import sys, struct, argparse
import numpy as np
ap = argparse.ArgumentParser()
ap.add_argument("inp"); ap.add_argument("out"); ap.add_argument("main_hz", type=float)
ap.add_argument("--scale", type=float, default=None, help="int16 -> int8 factor (default: 1/256, exact for HackRF recordings)")
ap.add_argument("--noise", type=float, default=0.0, help="add complex white noise, rms per component, in int8 units")
ap.add_argument("--seconds", type=float, default=None)
ap.add_argument("--add", action="append", default=[])
a = ap.parse_args()
with open(a.inp, "rb") as f:
    sr, cf = struct.unpack("<IQ", f.read(12)); f.seek(32)
    n = None if a.seconds is None else int(a.seconds * sr) * 2
    x = np.fromfile(f, dtype=np.int16, count=-1 if n is None else n).astype(np.float32)
assert sr == 2_000_000, sr
z = x[0::2] + 1j * x[1::2]
z *= (a.scale if a.scale is not None else 1 / 256)
if a.noise:   # receiver noise first, so --add's SNR is measured against it
    rng = np.random.default_rng(5)
    z += a.noise * (rng.standard_normal(len(z)) + 1j * rng.standard_normal(len(z)))
def load(path):
    with open(path, "rb") as f:
        r, c = struct.unpack("<IQ", f.read(12)); f.seek(32)
        v = np.fromfile(f, dtype=np.int16).astype(np.float32)
    return v[0::2] + 1j * v[1::2], r, c
for spec in a.add:
    path, t0, snr = spec.rsplit(":", 2)
    b, br, bc = load(path)
    assert br == sr
    on = np.abs(b) > 0.05 * np.abs(b).max()
    b = b[np.argmax(on): len(on) - np.argmax(on[::-1])]          # trim the silence around the burst
    b = b * np.exp(2j * np.pi * (bc - cf) / sr * np.arange(len(b)))
    seg = z[:sr // 2]
    Z = np.fft.fft(seg); fr = np.fft.fftfreq(len(seg), 1 / sr)
    noise = (np.abs(Z[np.abs(fr - (bc - cf)) < 31250]) ** 2).sum() / len(seg) ** 2
    sig = np.mean(np.abs(b) ** 2)
    b = b * np.sqrt(noise * 10 ** (float(snr) / 10) / sig)
    i0 = int(float(t0) * sr)
    z[i0:i0 + len(b)] += b[:max(0, len(z) - i0)]
    print(f"added {path} at {float(t0):.2f}s, {float(snr):+.0f} dB in-channel SNR, {len(b)/sr:.3f}s")
shift = 500_000 - (a.main_hz - cf)
z *= np.exp(2j * np.pi * shift / sr * np.arange(len(z)))
iq = np.empty(2 * len(z), np.int8)
iq[0::2] = np.clip(np.round(z.real), -127, 127); iq[1::2] = np.clip(np.round(z.imag), -127, 127)
iq.tofile(a.out)
print(f"{a.out}: {len(z)/sr:.2f}s, centre {cf/1e6:.4f} MHz, shifted {shift/1e3:+.1f} kHz, peak {np.abs(iq).max()}")
