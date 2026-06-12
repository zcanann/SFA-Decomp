#include "main/dll/df_partfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/resource.h"
#include "main/screen_transition.h"

extern undefined4 DAT_803de0af;

void FUN_800d7780(undefined param_1)
{
    DAT_803de0af = param_1;
    return;
}

/* Trivial 4b 0-arg blr leaves. */
void Checkpoint_release(void);

void Dummy04_func14_nop(void)
{
}

void Dummy04_func26_nop(void)
{
}

void Dummy04_func25_nop(void)
{
}

void Dummy04_func23_nop(void)
{
}

void Dummy04_func20_nop(void)
{
}

void Dummy04_func1F_nop(void)
{
}

void Dummy04_func1E_nop(void)
{
}

void Dummy04_func1C_nop(void)
{
}

void Dummy04_func1B_nop(void)
{
}

void Dummy04_func1A_nop(void)
{
}

void Dummy04_func19_nop(void)
{
}

void Dummy04_func18_nop(void)
{
}

void Dummy04_func17_nop(void)
{
}

void Dummy04_func16_nop(void)
{
}

void Dummy04_onSetupPlayer(void)
{
}

void Dummy04_func15_nop(void)
{
}

void Dummy04_func13_nop(void)
{
}

void Dummy04_func12_nop(void)
{
}

void Dummy04_func10_nop(void)
{
}

void Dummy04_func0E_nop(void)
{
}

void Dummy04_func0C_nop(void)
{
}

void Dummy04_onSelectSave(void)
{
}

void Dummy04_func08_nop(void)
{
}

void Dummy04_func07_nop(void)
{
}

void Dummy04_func04_nop(void)
{
}

void Dummy04_release(void)
{
}

void Dummy04_initialise(void)
{
}

void dll_0F_func19_nop(void);

/* 8b "li r3, N; blr" returners. */
int Dummy04_func24_ret_0(void) { return 0x0; }
int Dummy04_func22_ret_127(void) { return 0x7f; }
int Dummy04_func21_ret_0(void) { return 0x0; }
int Dummy04_func1D_ret_0(void) { return 0x0; }
int Dummy04_func11_ret_0(void) { return 0x0; }
int Dummy04_func0F_ret_0(void) { return 0x0; }
int Dummy04_func0D_ret_0(void) { return 0x0; }
int Dummy04_func0B_ret_0(void) { return 0x0; }
int Dummy04_func0A_ret_0(void) { return 0x0; }
int Dummy04_func05_ret_0(void) { return 0x0; }

/* sda21 accessors. */
extern u8 lbl_803DD42D;

/* Pattern wrappers. */

/* 12b 3-insn patterns. */

/* misc 8b leaves */

/* Pattern wrappers. */
int Dummy04_func03_ret_m1(void) { return -0x1; }

/* sda21 writers. */
extern u8 screenTransitionPause;

/* fcmp-eq-to-bool. */

/* multi-store leaf (single float broadcast). */

#include "main/dll/baddie_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */

static inline u8 Objfsa_IsWalkGroupActive(int groupIndex);

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */

/* player_init: memset constructor */

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */

/* player_updateVel */

/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */

/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */

/* UIController dispatch through the shared GameUI interface. */

/* player_setState */

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */
