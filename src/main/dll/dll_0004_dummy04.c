#include "main/dll/df_partfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/resource.h"
#include "main/screen_transition.h"

extern undefined4 DAT_803de0af;

/*
 * --INFO--
 *
 * Function: Checkpoint_func07
 * EN v1.0 Address: 0x800D6660
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800D6844
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800d7780
 * EN v1.0 Address: 0x800D7780
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800D7CFC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
#pragma peephole off
#pragma peephole reset

/* fcmp-eq-to-bool. */

/* multi-store leaf (single float broadcast). */

/* Checkpoint table initialiser. */

#pragma scheduling off
#pragma peephole off

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off

#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/baddie_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */

static inline u8 Objfsa_IsWalkGroupActive(int groupIndex);

/*
 * --INFO--
 *
 * Function: player_setScale
 * EN v1.0 Address: 0x800D8F90
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800D8FE0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_800d9090
 * EN v1.0 Address: 0x800D9090
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x800D9108
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on

/*
 * --INFO--
 *
 * Function: FUN_800d9de0
 * EN v1.0 Address: 0x800D9DE0
 * EN v1.0 Size: 1972b
 * EN v1.1 Address: 0x800DA4C8
 * EN v1.1 Size: 1772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800da594
 * EN v1.0 Address: 0x800DA594
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x800DABB4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800da5e8
 * EN v1.0 Address: 0x800DA5E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DAC0C
 * EN v1.1 Size: 1628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800da700
 * EN v1.0 Address: 0x800DA700
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800DB36C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800da850
 * EN v1.0 Address: 0x800DA850
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x800DB4B0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800db110
 * EN v1.0 Address: 0x800DB110
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x800DBCD8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800db47c
 * EN v1.0 Address: 0x800DB47C
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x800DBF88
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800db690
 * EN v1.0 Address: 0x800DB690
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x800DC158
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800db820
 * EN v1.0 Address: 0x800DB820
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: 0x800DC27C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800dd3e4
 * EN v1.0 Address: 0x800DD3E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DD8CC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800dd62c
 * EN v1.0 Address: 0x800DD62C
 * EN v1.0 Size: 2048b
 * EN v1.1 Address: 0x800DE41C
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800ddf84
 * EN v1.0 Address: 0x800DDF84
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DED20
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800ddf8c
 * EN v1.0 Address: 0x800DDF8C
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800DF0DC
 * EN v1.1 Size: 2428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_800de998
 * EN v1.0 Address: 0x800DE998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DFA58
 * EN v1.1 Size: 2400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: curves_findNearObj
 * EN v1.0 Address: 0x800E0134
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x800E03B8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: FUN_800dece0
 * EN v1.0 Address: 0x800DECE0
 * EN v1.0 Size: 1476b
 * EN v1.1 Address: 0x800E0670
 * EN v1.1 Size: 1572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on

/*
 * --INFO--
 *
 * Function: curves_lengthFn24
 * EN v1.0 Address: 0x800E0E18
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x800E109C
 * EN v1.1 Size: 1888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: curves_getPos
 * EN v1.0 Address: 0x800E1578
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x800E17FC
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: walkGroupFn_800db3e4
 * EN v1.0 Address: 0x800DB3E4
 * EN v1.0 Size: 1268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: isPointWithinPatchGroup
 * EN v1.0 Address: 0x800DB8D8
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: getPatchGroup
 * EN v1.0 Address: 0x800DBA4C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: isInWalkGroupOrPatch
 * EN v1.0 Address: 0x800DBBA4
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole on

/*
 * --INFO--
 *
 * Function: Objfsa_GetWalkGroupIndexAtPoint
 * EN v1.0 Address: 0x800DBCFC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off

/*
 * --INFO--
 *
 * Function: Objfsa_GetPatchGroupIdAtPoint
 * EN v1.0 Address: 0x800DBECC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: mathFn_800dbff0
 * EN v1.0 Address: 0x800DBFF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: RomCurve_findProjectedCurveFromStart
 * EN v1.0 Address: 0x800DFE64
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x800E1A4C
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling on
#pragma peephole on

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */

/* player_init: memset constructor */
#pragma scheduling off
#pragma peephole off

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */

/* player_updateVel */

/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */

#pragma scheduling on
#pragma peephole on

#pragma scheduling off
#pragma peephole off

/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */
#pragma peephole on

#pragma peephole off

#pragma peephole on

#pragma peephole off

/* UIController dispatch through the shared GameUI interface. */
#pragma scheduling on
#pragma peephole on

#pragma scheduling off
#pragma peephole off

/* player_setState */

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */
#pragma scheduling on

#pragma scheduling off

