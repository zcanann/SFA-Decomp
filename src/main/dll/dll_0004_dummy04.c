/*
 * dummy04 (DLL 0x0004) - an inert placeholder object DLL.
 *
 * Provides the full set of object-interface entry points the engine
 * expects (init/release, per-frame hooks func04..func26 (slots 06 and
 * 09 are absent from this DLL's interface), plus the
 * onSetupPlayer/onSelectSave game-flow callbacks), but every one is a
 * stub: the *_nop functions do nothing and the *_ret_* functions
 * return a fixed constant (0, 0x7f, or -1). Used to fill a DLL slot
 * with a known no-op so the dispatch tables stay valid.
 */

void Dummy04_func14_nop(void) {}
void Dummy04_func26_nop(void) {}
void Dummy04_func25_nop(void) {}
void Dummy04_func23_nop(void) {}
void Dummy04_func20_nop(void) {}
void Dummy04_func1F_nop(void) {}
void Dummy04_func1E_nop(void) {}
void Dummy04_func1C_nop(void) {}
void Dummy04_func1B_nop(void) {}
void Dummy04_func1A_nop(void) {}
void Dummy04_func19_nop(void) {}
void Dummy04_func18_nop(void) {}
void Dummy04_func17_nop(void) {}
void Dummy04_func16_nop(void) {}
void Dummy04_onSetupPlayer(void) {}
void Dummy04_func15_nop(void) {}
void Dummy04_func13_nop(void) {}
void Dummy04_func12_nop(void) {}
void Dummy04_func10_nop(void) {}
void Dummy04_func0E_nop(void) {}
void Dummy04_func0C_nop(void) {}
void Dummy04_onSelectSave(void) {}
void Dummy04_func08_nop(void) {}
void Dummy04_func07_nop(void) {}
void Dummy04_func04_nop(void) {}
void Dummy04_release(void) {}
void Dummy04_initialise(void) {}

int Dummy04_func24_ret_0(void) { return 0; }
int Dummy04_func22_ret_127(void) { return 0x7f; }
int Dummy04_func21_ret_0(void) { return 0; }
int Dummy04_func1D_ret_0(void) { return 0; }
int Dummy04_func11_ret_0(void) { return 0; }
int Dummy04_func0F_ret_0(void) { return 0; }
int Dummy04_func0D_ret_0(void) { return 0; }
int Dummy04_func0B_ret_0(void) { return 0; }
int Dummy04_func0A_ret_0(void) { return 0; }
int Dummy04_func05_ret_0(void) { return 0; }

int Dummy04_func03_ret_m1(void) { return -1; }
