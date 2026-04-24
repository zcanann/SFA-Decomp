#include "ghidra_import.h"
#include "main/dll/DR/gasventControl.h"

extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80021b8c();
extern uint FUN_80022264();
extern undefined4 FUN_80026ec4();
extern undefined4 FUN_8002b95c();
extern undefined4 FUN_8002b9a0();
extern void* FUN_8002becc();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_80036018();
extern undefined4 FUN_800372f8();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern int FUN_8005b068();
extern int FUN_8005b478();
extern uint FUN_800607f4();
extern int FUN_80060868();
extern int FUN_80060888();
extern undefined4 FUN_80070320();
extern undefined4 FUN_800803f8();
extern undefined8 FUN_80286824();
extern int FUN_80286834();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286880();
extern double FUN_80293900();

extern undefined4 DAT_803239f4;
extern undefined4 DAT_803239f8;
extern undefined4 DAT_803239fc;
extern undefined4* DAT_803dd740;
extern undefined4 DAT_803de798;
extern f64 DOUBLE_803e4f98;
extern f64 DOUBLE_803e4ff8;
extern f64 DOUBLE_803e5020;
extern f32 FLOAT_803e4f58;
extern f32 FLOAT_803e4fe8;
extern f32 FLOAT_803e4fec;
extern f32 FLOAT_803e4ff0;
extern f32 FLOAT_803e4ff4;
extern f32 FLOAT_803e5000;
extern f32 FLOAT_803e5004;
extern f32 FLOAT_803e5008;
extern f32 FLOAT_803e500c;
extern f32 FLOAT_803e5010;
extern f32 FLOAT_803e5014;
extern f32 FLOAT_803e5018;

/*
 * --INFO--
 *
 * Function: FUN_801a2b9c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A2B9C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a2b9c(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 7) = *(byte *)(iVar1 + 7) | 2;
  (**(code **)(*DAT_803dd740 + 4))(param_1,iVar1,5);
  FUN_800372f8(param_1,0x19);
  FUN_800372f8(param_1,0x16);
  FUN_80037a5c(param_1,8);
  *(undefined4 *)(param_1 + 0xf8) = 0;
  *(undefined2 *)(iVar1 + 0x44) = 0;
  *(undefined2 *)(iVar1 + 0x46) = 0;
  *(undefined *)(iVar1 + 0x15) = 0;
  *(undefined2 *)(iVar1 + 0x3c) = 0;
  *(undefined *)(iVar1 + 0x16) = 0;
  *(undefined *)(iVar1 + 0x17) = 0;
  *(undefined *)(iVar1 + 0x3e) = 0;
  *(undefined4 *)(iVar1 + 0x40) = 0;
  *(float *)(iVar1 + 0x30) = FLOAT_803e4f58;
  *(undefined *)(iVar1 + 0x49) = 0;
  FUN_800803f8((undefined4 *)(iVar1 + 0x18));
  FUN_800803f8((undefined4 *)(iVar1 + 0x1c));
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) | 1;
  *(byte *)(iVar1 + 0x48) =
       (*(char *)(param_2 + 0x19) < '\x01') << 7 | *(byte *)(iVar1 + 0x48) & 0x7f;
  *(byte *)(iVar1 + 0x48) = (*(short *)(param_2 + 0x1c) != 0) << 6 | *(byte *)(iVar1 + 0x48) & 0xbf;
  FUN_80036018(param_1);
  *(float *)(iVar1 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,
                                (int)*(short *)(*(int *)(param_1 + 0x54) + 0x5a) ^ 0x80000000) -
              DOUBLE_803e4f98);
  *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xdf;
  *(float *)(iVar1 + 0x38) = FLOAT_803e4f58;
  *(undefined4 *)(iVar1 + 0x10) = 0;
  (**(code **)(*DAT_803dd740 + 0x2c))(iVar1,1);
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x54) + 0xb2) = 1;
  }
  if (*(short *)(param_1 + 0x46) == 0x754) {
    *(byte *)(iVar1 + 0x4a) = *(byte *)(iVar1 + 0x4a) & 0xfb | 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a2d6c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A2D6C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801a2d6c(int param_1,uint param_2)
{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar1 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005b068(iVar1);
  if ((iVar1 == 0) || ((*(ushort *)(iVar1 + 4) & 8) == 0)) {
    uVar2 = 0;
  }
  else {
    for (iVar7 = 0; iVar7 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar7 = iVar7 + 1) {
      iVar5 = FUN_80060868(iVar1,iVar7);
      uVar3 = FUN_800607f4(iVar5);
      if (param_2 == uVar3) {
        *(uint *)(iVar5 + 0x10) = *(uint *)(iVar5 + 0x10) | 3;
      }
    }
    for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar7 = iVar7 + 1) {
      iVar4 = FUN_80060888(iVar1,iVar7);
      iVar5 = iVar4;
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar4 + 0x41); iVar6 = iVar6 + 1) {
        if (*(byte *)(iVar5 + 0x29) == param_2) {
          *(uint *)(iVar4 + 0x3c) = *(uint *)(iVar4 + 0x3c) | 2;
        }
        iVar5 = iVar5 + 8;
      }
    }
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801a2e98
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A2E98
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a2e98(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(int *)(*(int *)(param_1 + 0xb8) + 0xc) == 0)) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a2edc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A2EDC
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a2edc(void)
{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  
  iVar2 = FUN_80286834();
  iVar9 = *(int *)(iVar2 + 0x4c);
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar7 = (int)*(short *)(iVar9 + 0x1a);
  if (*(int *)(iVar8 + 0xc) == 0) {
    uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x1e));
    if (uVar3 == 0) {
      iVar11 = 0;
      for (iVar10 = 0; iVar5 = *(int *)(iVar2 + 0x54), iVar10 < *(char *)(iVar5 + 0x71);
          iVar10 = iVar10 + 1) {
        iVar6 = *(int *)(iVar5 + iVar11 + 0x7c);
        bVar1 = false;
        if (*(char *)(iVar5 + iVar10 + 0x75) == '\x05') {
          if (iVar7 == 0) {
            FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
            break;
          }
          uVar3 = 0;
          while (uVar3 != *(byte *)(iVar8 + 0x11)) {
            iVar5 = uVar3 * 4;
            uVar3 = uVar3 + 1;
            if (iVar6 == *(int *)(iVar8 + iVar5)) {
              bVar1 = true;
              uVar3 = (uint)*(byte *)(iVar8 + 0x11);
            }
          }
          if (!bVar1) {
            *(int *)(iVar8 + (uint)*(byte *)(iVar8 + 0x11) * 4) = iVar6;
            FUN_800201ac(*(byte *)(iVar8 + 0x11) + 0x2de,0);
            FUN_800201ac(*(byte *)(iVar8 + 0x11) + 0x2df,1);
            if ((int)*(short *)(iVar9 + 0x20) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar9 + 0x20),*(byte *)(iVar8 + 0x11) + 1);
            }
            DAT_803de798 = 300;
            iVar5 = *(byte *)(iVar8 + 0x11) + 1;
            if (iVar7 < iVar5) {
              for (iVar5 = 0; iVar5 < iVar7 + 1; iVar5 = iVar5 + 1) {
                FUN_800201ac(iVar5 + 0x2de,0);
              }
              FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
              FUN_801a2d6c(iVar2,(int)*(short *)(iVar9 + 0x1c));
              FUN_8002b95c(iVar2,2);
              *(undefined4 *)(iVar8 + 0xc) = 1;
            }
            else {
              *(char *)(iVar8 + 0x11) = (char)iVar5;
              FUN_8002b95c(iVar2,(uint)*(byte *)(iVar8 + 0x11));
            }
          }
        }
        iVar11 = iVar11 + 4;
      }
    }
    else {
      uVar4 = FUN_801a2d6c(iVar2,(int)*(short *)(iVar9 + 0x1c));
      *(undefined4 *)(iVar8 + 0xc) = uVar4;
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a30ac
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A30AC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a30ac(undefined2 *param_1,int param_2)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar3 + 0xc) = 0;
  FUN_8002b9a0((int)param_1,'Q');
  *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
  *(char *)(iVar3 + 0x10) = (char)*(undefined2 *)(param_2 + 0x1a);
  if ((int)*(short *)(param_2 + 0x20) != 0xffffffff) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x20));
    *(char *)(iVar3 + 0x11) = (char)uVar1;
    if ((uVar1 & 0xff) != 0) {
      FUN_8002b95c((int)param_1,(uint)*(byte *)(iVar3 + 0x11));
    }
  }
  FUN_800201ac(0x2de,1);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    uVar2 = FUN_801a2d6c((int)param_1,(int)*(short *)(param_2 + 0x1c));
    *(undefined4 *)(iVar3 + 0xc) = uVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3190
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A3190
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a3190(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined2 param_10,int param_11,undefined param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  double dVar5;
  
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) == 0) {
    uVar3 = 0;
  }
  else {
    puVar4 = FUN_8002becc(0x44,param_10);
    *puVar4 = param_10;
    *(undefined *)(puVar4 + 2) = 2;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    fVar1 = FLOAT_803e4fe8;
    puVar4[0x10] = (short)(int)(FLOAT_803e4fe8 * *(float *)(param_11 + 0x40));
    puVar4[0x11] = (short)(int)(fVar1 * *(float *)(param_11 + 0x44));
    puVar4[0x12] = (short)(int)(fVar1 * *(float *)(param_11 + 0x48));
    puVar4[0xd] = *(undefined2 *)(param_11 + 0x68);
    puVar4[0xe] = *(undefined2 *)(param_11 + 0x66);
    puVar4[0xf] = *(undefined2 *)(param_11 + 100);
    dVar5 = DOUBLE_803e4ff8;
    puVar4[0x16] = (short)(int)(*(float *)(param_11 + 0x1c) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_11 + 0x6d))
                                      - DOUBLE_803e4ff8));
    puVar4[0x17] = (short)(int)(*(float *)(param_11 + 0x20) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_11 + 0x6d))
                                      - dVar5));
    puVar4[0x18] = (short)(int)(*(float *)(param_11 + 0x24) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_11 + 0x6d))
                                      - dVar5));
    fVar1 = FLOAT_803e4fec;
    puVar4[0x19] = (short)(int)(FLOAT_803e4fec * *(float *)(param_11 + 0x28));
    puVar4[0x1b] = (short)(int)(fVar1 * *(float *)(param_11 + 0x30));
    puVar4[0x1a] = (short)(int)(fVar1 * *(float *)(param_11 + 0x2c));
    fVar1 = FLOAT_803e4ff0;
    puVar4[0x13] = (short)(int)(FLOAT_803e4ff0 * *(float *)(param_11 + 0x34));
    puVar4[0x14] = (short)(int)(fVar1 * *(float *)(param_11 + 0x38));
    puVar4[0x15] = (short)(int)(fVar1 * *(float *)(param_11 + 0x3c));
    *(undefined *)(puVar4 + 0xc) = param_12;
    dVar5 = (double)FLOAT_803e4ff4;
    fVar1 = *(float *)(param_9 + 8);
    *(char *)((int)puVar4 + 0x3d) =
         (char)(int)(dVar5 * (double)(float)((double)fVar1 /
                                            (double)*(float *)(*(int *)(param_9 + 0x50) + 4)));
    puVar4[0x1c] = (short)*(undefined4 *)(param_11 + 0x5c);
    puVar4[0x1d] = (short)(int)*(float *)(param_11 + 0x58);
    uVar3 = FUN_8002e088((double)fVar1,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,
                         5,*(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,param_14,param_15,
                         param_16);
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801a3434
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A3434
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3434(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801a3674
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801A3674
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a3674(int param_1,int param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined8 local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  FUN_80021b8c((ushort *)(param_3 + 0x1a),(float *)(param_2 + 0x10));
  *(float *)(param_2 + 0x4c) =
       *(float *)(param_2 + 0x10) * *(float *)(param_1 + 8) + *(float *)(param_3 + 8);
  *(float *)(param_2 + 0x50) =
       *(float *)(param_2 + 0x14) * *(float *)(param_1 + 8) + *(float *)(param_3 + 0xc);
  *(float *)(param_2 + 0x54) =
       *(float *)(param_2 + 0x18) * *(float *)(param_1 + 8) + *(float *)(param_3 + 0x10);
  *(undefined2 *)(param_2 + 0x68) = *(undefined2 *)(param_3 + 0x1a);
  *(undefined2 *)(param_2 + 0x66) = *(undefined2 *)(param_3 + 0x1c);
  *(undefined2 *)(param_2 + 100) = *(undefined2 *)(param_3 + 0x1e);
  uStack_44 = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_48 = 0x43300000;
  local_50[0] = *(float *)(param_2 + 0x10) -
                (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5020);
  uStack_3c = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_40 = 0x43300000;
  local_54 = *(float *)(param_2 + 0x14) -
             (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e5020);
  local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x24) ^ 0x80000000);
  local_58 = *(float *)(param_2 + 0x18) - (float)(local_38 - DOUBLE_803e5020);
  dVar4 = FUN_80293900((double)(local_58 * local_58 +
                               local_50[0] * local_50[0] + local_54 * local_54));
  dVar5 = (double)FLOAT_803e5000;
  if (dVar4 != dVar5) {
    local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2c) ^ 0x80000000);
    dVar4 = (double)((float)(local_38 - DOUBLE_803e5020) / (float)((double)FLOAT_803e5008 * dVar4));
    if ((((double)local_50[0] != dVar5) || ((double)local_54 != dVar5)) ||
       ((double)local_58 != dVar5)) {
      FUN_80070320(local_50,&local_54,&local_58);
    }
    *(float *)(param_2 + 0x40) = (float)((double)local_50[0] * dVar4);
    *(float *)(param_2 + 0x44) = (float)((double)local_54 * dVar4);
    *(float *)(param_2 + 0x48) = (float)((double)local_58 * dVar4);
    uVar3 = (uint)(FLOAT_803e500c * (float)((double)FLOAT_803e5010 + dVar4));
    local_38 = (double)(longlong)(int)uVar3;
    uStack_3c = FUN_80022264(0,uVar3);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(param_2 + 0x1c) =
         (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e5020) / FLOAT_803e5014;
    uStack_44 = FUN_80022264(0,uVar3);
    uStack_44 = uStack_44 ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(param_2 + 0x20) =
         (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5020) / FLOAT_803e5014;
    uStack_2c = FUN_80022264(0,uVar3);
    dVar4 = DOUBLE_803e5020;
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(param_2 + 0x24) =
         (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5020) / FLOAT_803e5014;
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x30) ^ 0x80000000);
    dVar4 = (double)((float)(local_28 - dVar4) / FLOAT_803e4ff0);
    if (FLOAT_803e5000 < *(float *)(param_1 + 0x24)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 1;
    }
    if (FLOAT_803e5000 < *(float *)(param_1 + 0x2c)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 2;
    }
    if (FLOAT_803e5000 < *(float *)(param_2 + 0x1c)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 4;
    }
    if (FLOAT_803e5000 < *(float *)(param_2 + 0x20)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 8;
    }
    if (FLOAT_803e5000 < *(float *)(param_2 + 0x24)) {
      *(byte *)(param_2 + 0x6c) = *(byte *)(param_2 + 0x6c) | 0x10;
    }
    uVar3 = (uint)(FLOAT_803e500c * (float)((double)FLOAT_803e5010 + dVar4));
    local_28 = (double)(longlong)(int)uVar3;
    uStack_2c = FUN_80022264(0,uVar3);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(param_2 + 0x28) =
         (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5020) / FLOAT_803e500c;
    uVar2 = FUN_80022264(0,uVar3);
    local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(param_2 + 0x2c) = (float)(local_38 - DOUBLE_803e5020) / FLOAT_803e500c;
    uStack_3c = FUN_80022264(0,uVar3);
    dVar5 = DOUBLE_803e5020;
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    *(float *)(param_2 + 0x30) =
         (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e5020) / FLOAT_803e500c;
    *(float *)(param_2 + 0x34) = (float)((double)local_50[0] * dVar4);
    *(float *)(param_2 + 0x38) = (float)((double)local_54 * dVar4 - (double)FLOAT_803e5018);
    *(float *)(param_2 + 0x3c) = (float)((double)local_58 * dVar4);
    if ((int)*(short *)(param_3 + 0x2e) != 0) {
      local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x2e) ^ 0x80000000);
      *(float *)(param_2 + 0x58) = (float)(local_28 - dVar5);
    }
    *(uint *)(param_2 + 0x5c) = (uint)*(ushort *)(param_3 + 0x38);
    if (*(short *)(param_3 + 0x38) == 0) {
      *(undefined4 *)(param_2 + 0x60) = 0xffffffff;
    }
    else {
      uVar3 = FUN_80022264(0,100);
      iVar1 = (uint)*(ushort *)(param_3 + 0x38) * (uVar3 + 100);
      iVar1 = iVar1 / 200 + (iVar1 >> 0x1f);
      *(int *)(param_2 + 0x60) = iVar1 - (iVar1 >> 0x1f);
    }
  }
  return;
}
