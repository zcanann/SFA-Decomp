#include "ghidra_import.h"
#include "main/dll/NW/NWmammoth.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80020000();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern double FUN_80021794();
extern undefined4 FUN_800217c8();
extern undefined4 FUN_8002ad08();
extern byte FUN_8002b11c();
extern undefined4 FUN_8002b128();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035ff8();
extern int FUN_80036974();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800375e4();
extern undefined4 FUN_80037a5c();
extern int FUN_80064248();
extern int FUN_80065fcc();
extern undefined4 FUN_80099c40();
extern undefined4 FUN_801d0e2c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e5f58;
extern f32 FLOAT_803e5f20;
extern f32 FLOAT_803e5f2c;
extern f32 FLOAT_803e5f38;
extern f32 FLOAT_803e5f40;
extern f32 FLOAT_803e5f78;
extern f32 FLOAT_803e5f7c;
extern f32 FLOAT_803e5f80;
extern f32 FLOAT_803e5f84;
extern f32 FLOAT_803e5f88;
extern f32 FLOAT_803e5f8c;

/*
 * --INFO--
 *
 * Function: FUN_801d1b54
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D1B54
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d1b54(int param_1)
{
  FUN_8003709c(param_1,0x47);
  FUN_8003709c(param_1,0x31);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d1b90
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D1B90
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d1b90(int *param_1)
{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *local_70;
  int aiStack_6c [20];
  char local_1c;
  
  iVar5 = param_1[0x2e];
  iVar4 = param_1[0x13];
  if (((*(ushort *)(param_1 + 0x2c) & 0x1000) == 0) &&
     (((*(byte *)(iVar5 + 0x137) & 8) != 0 || ((*(ushort *)(param_1[0x15] + 0x60) & 8) != 0)))) {
    iVar1 = FUN_80065fcc((double)(float)param_1[3],(double)(float)param_1[4],
                         (double)(float)param_1[5],param_1,&local_70,0,0);
    iVar3 = 0;
    puVar2 = local_70;
    if (0 < iVar1) {
      do {
        if (*(float *)*puVar2 < FLOAT_803e5f2c + (float)param_1[4]) {
          param_1[4] = *(int *)local_70[iVar3];
          break;
        }
        puVar2 = puVar2 + 1;
        iVar3 = iVar3 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar1 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x2,aiStack_6c,param_1,8,0xffffffff,
                         0xff,0x14);
    if (((*(char *)(iVar4 + 0x18) == '\x04') && (iVar1 != 0)) && (local_1c == '\r')) {
      *(byte *)(iVar5 + 0x137) = *(byte *)(iVar5 + 0x137) | 4;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d1cdc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D1CDC
 * EN v1.1 Size: 652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d1cdc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  ushort *puVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  float *pfVar5;
  int in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  uint local_38;
  int local_34 [11];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar1 = (ushort *)FUN_80286840();
  pfVar7 = *(float **)(puVar1 + 0x5c);
  iVar6 = *(int *)(puVar1 + 0x26);
  iVar2 = FUN_8002bac4();
  iVar3 = FUN_8002ba84();
  bVar4 = FUN_8002b11c((int)puVar1);
  if (bVar4 == 0) {
    if (*(char *)((int)pfVar7 + 0x136) == '\b') {
      while (iVar2 = FUN_800375e4((int)puVar1,&local_38,(uint *)0x0,(uint *)0x0), iVar2 != 0) {
        if (local_38 == 0x7000b) {
          puVar1[3] = puVar1[3] | 0x4000;
          FUN_80035ff8((int)puVar1);
          FUN_80020000((int)*(short *)(pfVar7 + 0x4d));
          FUN_800201ac(0x12e,0);
          if (puVar1[0x23] == 0x658) {
            FUN_80099c40((double)FLOAT_803e5f40,puVar1,0xff,0x28);
          }
          else {
            FUN_80099c40((double)FLOAT_803e5f40,puVar1,6,0x28);
          }
          FUN_8000bb38((uint)puVar1,0x58);
        }
      }
    }
    else {
      if (*(char *)((int)pfVar7 + 0x139) != '\0') {
        *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(iVar6 + 8);
        *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(iVar6 + 0x10);
        *(undefined *)(puVar1 + 0x1b) = 0xff;
        *(undefined *)((int)pfVar7 + 0x139) = 0;
      }
      pfVar7[0x43] = pfVar7[0x42];
      dVar8 = FUN_80021794((float *)(iVar2 + 0x18),(float *)(puVar1 + 0xc));
      if (iVar3 == 0) {
        dVar8 = FUN_80293900(dVar8);
        pfVar7[0x42] = (float)dVar8;
      }
      else {
        dVar9 = FUN_80021794((float *)(iVar3 + 0x18),(float *)(puVar1 + 0xc));
        if (dVar9 <= dVar8) {
          dVar8 = FUN_80293900(dVar9);
          pfVar7[0x42] = (float)dVar8;
        }
        else {
          dVar8 = FUN_80293900(dVar8);
          pfVar7[0x42] = (float)dVar8;
        }
        param_2 = (double)pfVar7[0x42];
        local_34[2] = (int)*(byte *)(iVar6 + 0x1f);
        local_34[1] = 0x43300000;
        dVar8 = DOUBLE_803e5f58;
        if (param_2 < (double)(float)((double)CONCAT44(0x43300000,local_34[2]) - DOUBLE_803e5f58)) {
          in_r7 = **(int **)(iVar3 + 0x68);
          dVar8 = (double)(**(code **)(in_r7 + 0x28))(iVar3,puVar1,0,1);
        }
      }
      pfVar5 = (float *)0x0;
      iVar2 = FUN_80036974((int)puVar1,local_34,(int *)0x0,(uint *)0x0);
      if (iVar2 != 0) {
        if (iVar2 == 0x10) {
          dVar8 = (double)FUN_8002b128(puVar1,300);
        }
        else {
          pfVar5 = (float *)0x0;
          in_r7 = 0;
          in_r8 = 1;
          dVar8 = (double)FUN_8002ad08(puVar1,0xf,200,0,0,1);
          if (*(short *)(local_34[0] + 0x46) != 0x416) {
            if ((*(byte *)((int)pfVar7 + 0x137) & 0x10) == 0) {
              dVar8 = (double)FUN_8000bb38((uint)puVar1,0x9d);
            }
            *(byte *)((int)pfVar7 + 0x137) = *(byte *)((int)pfVar7 + 0x137) | 0x10;
          }
        }
      }
      FUN_801d0e2c(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(short *)puVar1,
                   pfVar7,iVar6,pfVar5,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d1f68
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D1F68
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d1f68(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}
