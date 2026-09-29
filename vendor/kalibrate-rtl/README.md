# Kalibrate attribution

`engine/gsm_calibration.py` adapts the adaptive line enhancer and interpolated
FFT frequency detector from `src/fcch_detector.cc` in
https://github.com/steve-m/kalibrate-rtl at commit
`340003eb0846b069c3edef19ed3363b8ac7b5215` (Joshua Lackey, 2010).
The upstream BSD license is reproduced in COPYING and the Python source.

This is a Python adaptation, not the unmodified `kal` executable. It reuses the
scanner's rtl_tcp connection, has no USB/FFTW/compiler dependency, rejects
unbounded tones, returns multiple bursts per block, and validates estimates
across channels. No mobile traffic is decoded or retained.
