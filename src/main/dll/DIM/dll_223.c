#include "ghidra_import.h"
#include "main/dll/DIM/dll_223.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017a7c();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_8005d17c();
extern undefined4 FUN_801141e8();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_801ba2e0();
extern undefined4 FUN_801ba6d8();
extern undefined4 FUN_801ba9ec();
extern undefined4 FUN_801bab8c();
extern undefined4 FUN_801babd4();
extern undefined4 FUN_801bad7c();
extern undefined4 FUN_801baefc();
extern undefined4 FUN_801bb080();
extern undefined4 FUN_801bb2a0();
extern undefined4 FUN_801bb450();
extern undefined4 FUN_801bb5e8();
extern undefined4 FUN_801bb798();
extern undefined4 FUN_801bb954();
extern undefined4 FUN_801bbbc8();
extern undefined4 FUN_801bbd68();
extern undefined4 FUN_801bbea0();
extern undefined4 DIMboss_updateState();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_802c2ab8;
extern undefined4 DAT_802c2abc;
extern undefined4 DAT_802c2ac0;
extern undefined4 DAT_802c2ac4;
extern undefined4 DAT_803ad63c;
extern undefined4 DAT_803adc4d;
extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc64;
extern undefined4 DAT_803adc68;
extern undefined4 DAT_803adc6c;
extern undefined4 DAT_803adc70;
extern undefined4 DAT_803adc74;
extern undefined4 DAT_803adc78;
extern undefined4 DAT_803adc7c;
extern undefined4 DAT_803adc80;
extern undefined4 DAT_803adc84;
extern undefined4 DAT_803adc88;
extern undefined4 DAT_803adc8c;
extern undefined4 DAT_803adc90;
extern undefined4 DAT_803adc94;
extern undefined4 DAT_803adc98;
extern undefined4 DAT_803adc9c;
extern undefined4 DAT_803adca0;
extern undefined4 DAT_803adca4;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4 DAT_803de804;
extern undefined4 DAT_803de808;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5870;
extern f32 FLOAT_803e58c0;
extern f32 FLOAT_803e5910;
extern f32 FLOAT_803e5918;
extern f32 FLOAT_803e5920;

/*
 * --INFO--
 *
 * Function: DIMboss_init
 * EN v1.0 Address: 0x801BDCF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801BDD60
 * EN v1.1 Size: 808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_init(int param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: DIMboss_initialise
 * EN v1.0 Address: 0x801BDCFC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801BE088
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMboss_initialise(void)
{
  FUN_801bdd1c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bdd1c
 * EN v1.0 Address: 0x801BDD1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801BE0A8
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bdd1c(void)
{
}

/*
 * --INFO--
 *
 * Function: DIMbossgut_render
 * EN v1.0 Address: 0x801BDD20
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801BE1C0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossgut_render(void)
{
  int iVar1;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    FUN_8002fc3c((double)FLOAT_803e5918,(double)FLOAT_803dc074);
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: DIMbossgut_init
 * EN v1.0 Address: 0x801BDD6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801BE240
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMbossgut_init(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                     undefined4 param_13,undefined4 param_14,undefined4 param_15,
                     undefined4 param_16)
{
}
