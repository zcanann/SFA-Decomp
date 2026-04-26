#include "ghidra_import.h"
#include "main/dll/flybaddie.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_801c9018();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e5d68;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5d70;
extern f32 FLOAT_803e5d74;

/*
 * --INFO--
 *
 * Function: FUN_801c9544
 * EN v1.0 Address: 0x801C9544
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801C9604
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9544(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *puVar2 = 0;
  }
  FUN_80006b4c();
  FUN_80037180(param_1,0xb);
  FUN_800067c0((int *)0xd8,0);
  FUN_800067c0((int *)0xd9,0);
  FUN_800067c0((int *)0x8,0);
  FUN_800067c0((int *)0xe,0);
  FUN_80017698(0xefa,0);
  FUN_80017698(0xcbb,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c95e8
 * EN v1.0 Address: 0x801C95E8
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C96A8
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c95e8(void)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    if (*piVar2 != 0) {
      FUN_800175cc((double)FLOAT_803e5d70,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_800175cc((double)FLOAT_803e5d70,*piVar2,'\x01');
    }
    FUN_8003b818(iVar1);
    FUN_8008111c((double)FLOAT_803e5d70,(double)FLOAT_803e5d70,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9680
 * EN v1.0 Address: 0x801C9680
 * EN v1.0 Size: 1180b
 * EN v1.1 Address: 0x801C9764
 * EN v1.1 Size: 916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9680(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar3 = FUN_80017a98();
  if (iVar3 != 0) {
    if ((*(int *)(param_9 + 0x7a) != 0) &&
       (*(int *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + -1, *(int *)(param_9 + 0x7a) == 0)) {
      uVar7 = FUN_80080f28(7,'\x01');
      uVar7 = FUN_80006728(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           iVar3,0xd4,0,in_r7,in_r8,in_r9,in_r10);
      uVar7 = FUN_80006728(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           iVar3,0xd5,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80006728(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar3,0x222
                   ,0,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_801c9018(param_9);
    FUN_801d8308(iVar6 + 4,2,-1,-1,0xdd3,(int *)0xe);
    FUN_801d8480(iVar6 + 4,1,-1,-1,0xcbb,(int *)0x8);
    FUN_801d8308(iVar6 + 4,4,-1,-1,0xcbb,(int *)0xc4);
    bVar1 = *(byte *)(iVar6 + 0x14);
    if (bVar1 != 3) {
      if (bVar1 < 3) {
        if (bVar1 == 1) {
          param_9[3] = param_9[3] | 0x4000;
          if (*(char *)(iVar6 + 0x15) < '\0') {
            *(undefined *)(iVar6 + 0x14) = 2;
            FUN_80017698(0x16a,1);
          }
        }
        else if (bVar1 == 0) {
          param_9[3] = param_9[3] & 0xbfff;
          fVar2 = *(float *)(iVar6 + 8) - FLOAT_803dc074;
          *(float *)(iVar6 + 8) = fVar2;
          if (fVar2 <= FLOAT_803e5d74) {
            FUN_80006824((uint)param_9,0x343);
            uVar4 = FUN_80017760(500,1000);
            *(float *)(iVar6 + 8) =
                 (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e5d68);
          }
          if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
            cVar5 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0x56),1);
            if (cVar5 != '\0') {
              (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0x56),1,0);
            }
            *(undefined *)(iVar6 + 0x14) = 1;
            FUN_80017698(0xdd3,1);
            *param_9 = 0x7fff;
            (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
            FUN_800067c0((int *)0xd8,1);
          }
        }
        else {
          uVar4 = FUN_80017690(0x16b);
          if (uVar4 == 0) {
            uVar4 = FUN_80017690(0x16c);
            if (uVar4 != 0) {
              *(undefined *)(iVar6 + 0x14) = 5;
              FUN_80017698(0xc72,1);
              *(undefined2 *)(iVar6 + 0xc) = 10;
            }
          }
          else {
            *(undefined *)(iVar6 + 0x14) = 4;
            *(undefined2 *)(iVar6 + 0xc) = 0;
          }
        }
      }
      else if (bVar1 == 5) {
        *(undefined *)(iVar6 + 0x14) = 0;
        *(byte *)(iVar6 + 0x15) = *(byte *)(iVar6 + 0x15) & 0x7f;
        *(undefined2 *)(iVar6 + 0xc) = 0;
        FUN_80017698(0xdd3,0);
        FUN_80017698(0x15f,0);
        FUN_80017698(0x16a,0);
        FUN_80017698(0x16b,0);
        FUN_80017698(0x16c,0);
        FUN_80017698(0xc72,0);
        FUN_80017698(0xc73,0);
      }
      else if (bVar1 < 5) {
        *(undefined *)(iVar6 + 0x14) = 5;
        FUN_80006770(3);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
        FUN_80017698(0xdd3,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_release
 * EN v1.0 Address: 0x801C9658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_shrine_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dbsh_shrine_initialise
 * EN v1.0 Address: 0x801C965C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_shrine_initialise(void)
{
}
