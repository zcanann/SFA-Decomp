#include "ghidra_import.h"
#include "main/dll/DIM/DIM2icicle.h"

extern undefined4 FUN_80003494();
extern undefined8 FUN_80008cbc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e670();
extern undefined4 FUN_8000e69c();
extern undefined4 FUN_8000faf8();
extern undefined4 FUN_80014acc();
extern undefined4 FUN_8001d6e4();
extern undefined4 FUN_8001d7d8();
extern undefined4 FUN_8001d7e0();
extern undefined4 FUN_8001d7f4();
extern undefined4 FUN_8001daa4();
extern undefined4 FUN_8001dab8();
extern undefined4 FUN_8001dadc();
extern undefined4 FUN_8001db7c();
extern undefined4 FUN_8001dbb4();
extern undefined4 FUN_8001dbf0();
extern undefined4 FUN_8001dc18();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001dcfc();
extern undefined4 FUN_8001de04();
extern undefined4 FUN_8001de4c();
extern void* FUN_8001f58c();
extern undefined8 FUN_800201ac();
extern uint FUN_80022264();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_80036018();
extern int FUN_80036974();
extern undefined4 FUN_800379bc();
extern uint FUN_80038498();
extern undefined4 FUN_80038524();
extern undefined4 FUN_80055464();
extern undefined4 FUN_80089734();
extern undefined4 FUN_8008986c();
extern undefined4 FUN_8008999c();
extern undefined8 FUN_8012e0b8();
extern undefined4 FUN_801bb8dc();
extern undefined4 FUN_80247bf8();
extern undefined8 FUN_80286824();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_8028688c();
extern uint FUN_80296164();

extern undefined4 DAT_802c2ac8;
extern undefined4 DAT_802c2acc;
extern undefined4 DAT_802c2ad0;
extern undefined4 DAT_802c2ad4;
extern undefined4 DAT_80326620;
extern undefined4 DAT_80326624;
extern undefined4 DAT_803266f8;
extern undefined4 DAT_803266fc;
extern undefined4 DAT_80326700;
extern undefined4 DAT_80326704;
extern undefined4 DAT_803ad5d0;
extern undefined4 DAT_803ad5d4;
extern undefined4 DAT_803ad5d8;
extern undefined4 DAT_803ad5dc;
extern undefined4 DAT_803ad5e8;
extern undefined4 DAT_803ad5ec;
extern undefined4 DAT_803ad5f0;
extern undefined4 DAT_803ad5f4;
extern undefined4 DAT_803ad5f6;
extern undefined4 DAT_803ad5f8;
extern undefined4 DAT_803ad5fc;
extern undefined4 DAT_803ad600;
extern undefined4 DAT_803ad604;
extern undefined4 DAT_803ad608;
extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc78;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4* DAT_803de808;
extern undefined4 DAT_803de80c;
extern f64 DOUBLE_803e5878;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e5854;
extern f32 FLOAT_803e585c;
extern f32 FLOAT_803e5860;
extern f32 FLOAT_803e5864;
extern f32 FLOAT_803e5870;
extern f32 FLOAT_803e5884;
extern f32 FLOAT_803e588c;
extern f32 FLOAT_803e5890;
extern f32 FLOAT_803e58a8;
extern f32 FLOAT_803e58c0;
extern f32 FLOAT_803e58c4;
extern f32 FLOAT_803e58c8;
extern f32 FLOAT_803e58cc;
extern f32 FLOAT_803e58d0;
extern f32 FLOAT_803e58d4;
extern f32 FLOAT_803e58d8;
extern f32 FLOAT_803e58dc;
extern f32 FLOAT_803e58e0;
extern f32 FLOAT_803e58e4;
extern f32 FLOAT_803e58e8;
extern f32 FLOAT_803e58ec;
extern f32 FLOAT_803e58f0;
extern f32 FLOAT_803e58f4;
extern f32 FLOAT_803e58f8;
extern f32 FLOAT_803e58fc;
extern f32 FLOAT_803e5900;
extern f32 FLOAT_803e5904;
extern f32 FLOAT_803e5908;
extern f32 FLOAT_803e590c;

/*
 * --INFO--
 *
 * Function: FUN_801bb99c
 * EN v1.0 Address: 0x801BB99C
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bb99c(int param_1,char param_2)
{
  int *piVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar2;
  double dVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  piVar2 = *(int **)(*(int *)(param_1 + 0xb8) + 0x40c);
  if (*piVar2 == 0) {
    piVar1 = FUN_8001f58c(0,'\x01');
    *piVar2 = (int)piVar1;
    if (*piVar2 != 0) {
      FUN_8001dbf0(*piVar2,2);
      dVar3 = (double)(float)piVar2[0x17];
      dVar4 = (double)(float)piVar2[0x18];
      FUN_8001de4c((double)(float)piVar2[0x16],dVar3,dVar4,(int *)*piVar2);
      if (param_2 == '\0') {
        FUN_8001dbb4(*piVar2,0xff,0,0,0xff);
        FUN_8001dadc(*piVar2,0xff,0,0,0xff);
        FUN_8001d7f4((double)FLOAT_803e58c4,dVar3,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar2,0,0xff
                     ,0,0,0xc0,in_r9,in_r10);
      }
      else {
        FUN_8001dbb4(*piVar2,0,0xff,0,0xff);
        FUN_8001dadc(*piVar2,0,0xff,0,0xff);
        FUN_8001d7f4((double)FLOAT_803e58c0,dVar3,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar2,0,0,
                     0xff,0,0xc0,in_r9,in_r10);
      }
      FUN_8001dcfc((double)FLOAT_803e58c4,(double)FLOAT_803e58c8,*piVar2);
      FUN_8001dc18(*piVar2,1);
      FUN_8001dc30((double)FLOAT_803e5870,*piVar2,'\x01');
      FUN_8001db7c(*piVar2,0x40,0,0,0x40);
      FUN_8001daa4(*piVar2,0x40,0,0,0x40);
      FUN_8001d6e4(*piVar2,2,0x28);
      FUN_8001de04(*piVar2,1);
      FUN_8001d7d8((double)FLOAT_803e5854,*piVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bbb4c
 * EN v1.0 Address: 0x801BBB4C
 * EN v1.0 Size: 1452b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bbb4c(void)
{
  float fVar1;
  short sVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  double in_f28;
  double dVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  undefined uStack_b8;
  undefined local_b7;
  undefined local_b6;
  undefined local_b5;
  float afStack_b4 [3];
  float local_a8;
  float local_98;
  float local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar12 = FUN_80286824();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  piVar7 = *(int **)((int)uVar12 + 0x40c);
  piVar4 = (int *)*piVar7;
  if (piVar4 != (int *)0x0) {
    if (*(short *)((int)uVar12 + 0x402) == 1) {
      FUN_8001de4c((double)(float)piVar7[0x16],(double)(float)piVar7[0x17],
                   (double)(float)piVar7[0x18],piVar4);
    }
    else {
      FUN_8001de4c((double)(float)piVar7[0x10],(double)(float)piVar7[0x11],
                   (double)(float)piVar7[0x12],piVar4);
    }
    FUN_8001dab8(*piVar7,&local_b5,&local_b6,&local_b7,&uStack_b8);
    FUN_8001d7e0(*piVar7,local_b5,local_b6,local_b7,0xc0);
    iVar6 = *piVar7;
    if ((*(char *)(iVar6 + 0x2f8) != '\0') && (*(char *)(iVar6 + 0x4c) != '\0')) {
      sVar2 = (ushort)*(byte *)(iVar6 + 0x2f9) + (short)*(char *)(iVar6 + 0x2fa);
      if (sVar2 < 0) {
        sVar2 = 0;
        *(undefined *)(iVar6 + 0x2fa) = 0;
      }
      else if (0xc < sVar2) {
        uVar5 = FUN_80022264(0xfffffff4,0xc);
        sVar2 = sVar2 + (short)uVar5;
        if (0xff < sVar2) {
          sVar2 = 0xff;
          *(undefined *)(*piVar7 + 0x2fa) = 0;
        }
      }
      *(char *)(*piVar7 + 0x2f9) = (char)sVar2;
    }
  }
  if ((DAT_803de800 & 0x200) != 0) {
    FUN_80038524(iVar3,7,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x400) != 0) {
    FUN_80038524(iVar3,8,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x800) != 0) {
    FUN_80038524(iVar3,9,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x1000) != 0) {
    FUN_80038524(iVar3,10,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,0);
    iVar6 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b7,&DAT_803ad5dc,0x200001,0xffffffff,0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0xf);
  }
  if ((DAT_803de800 & 0x10) != 0) {
    uVar5 = FUN_80038498(iVar3,0xb);
    FUN_80003494((uint)afStack_b4,uVar5,0x30);
    local_a8 = FLOAT_803e5870;
    local_98 = FLOAT_803e5870;
    local_88 = FLOAT_803e5870;
    iVar6 = 0;
    dVar9 = (double)FLOAT_803e58cc;
    dVar10 = (double)(float)(dVar9 * (double)FLOAT_803e58d0);
    dVar11 = (double)FLOAT_803e5864;
    dVar8 = DOUBLE_803e5878;
    do {
      uStack_7c = FUN_80022264(0xffffffe7,0x19);
      uStack_7c = uStack_7c ^ 0x80000000;
      local_80 = 0x43300000;
      DAT_803ad5e8 = (float)((double)CONCAT44(0x43300000,uStack_7c) - dVar8);
      uStack_74 = FUN_80022264(0xffffffe7,0x19);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      DAT_803ad5ec = (float)((double)CONCAT44(0x43300000,uStack_74) - dVar8);
      DAT_803ad5f0 = (float)dVar9;
      DAT_803ad5d0 = (float)((double)DAT_803ad5e8 / dVar10);
      DAT_803ad5d4 = (float)((double)DAT_803ad5ec / dVar10);
      DAT_803ad5d8 = (float)dVar11;
      FUN_80247bf8(afStack_b4,&DAT_803ad5d0,&DAT_803ad5d0);
      FUN_80038524(iVar3,0xb,&DAT_803ad5e8,&DAT_803ad5ec,&DAT_803ad5f0,1);
      (**(code **)(*DAT_803dd708 + 8))(iVar3,0x4b8,&DAT_803ad5dc,0x200001,0xffffffff,&DAT_803ad5d0);
      iVar6 = iVar6 + 1;
    } while (iVar6 < 5);
  }
  piVar7[10] = (int)FLOAT_803e5870;
  piVar7[0xb] = (int)FLOAT_803e58d4;
  piVar7[0xc] = (int)FLOAT_803e58d8;
  piVar7[9] = (int)FLOAT_803e58dc;
  *(undefined2 *)(piVar7 + 8) = 0;
  *(undefined2 *)((int)piVar7 + 0x1e) = 0;
  *(undefined2 *)(piVar7 + 7) = 0;
  FUN_80038524(iVar3,0xd,(float *)(piVar7 + 10),piVar7 + 0xb,(float *)(piVar7 + 0xc),1);
  FUN_80038524(iVar3,0xd,(float *)(piVar7 + 4),piVar7 + 5,(float *)(piVar7 + 6),0);
  FUN_80038524(iVar3,0xb,(float *)(piVar7 + 0x10),piVar7 + 0x11,(float *)(piVar7 + 0x12),0);
  piVar7[0x16] = (int)FLOAT_803e5870;
  piVar7[0x17] = (int)FLOAT_803e58e0;
  piVar7[0x18] = (int)FLOAT_803e5860;
  piVar7[0x15] = (int)FLOAT_803e58dc;
  *(undefined2 *)(piVar7 + 0x14) = 0;
  *(undefined2 *)((int)piVar7 + 0x4e) = 0;
  *(undefined2 *)(piVar7 + 0x13) = 0;
  FUN_80038524(iVar3,0xc,(float *)(piVar7 + 0x16),piVar7 + 0x17,(float *)(piVar7 + 0x18),1);
  uVar5 = FUN_80038498(iVar3,0);
  FUN_80003494((uint)(piVar7 + 0x19),uVar5,0x30);
  fVar1 = FLOAT_803e5870;
  piVar7[0x1c] = (int)FLOAT_803e5870;
  piVar7[0x20] = (int)fVar1;
  piVar7[0x24] = (int)fVar1;
  DAT_803de800 = DAT_803de800 & 0xffffe1ef;
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bc0f8
 * EN v1.0 Address: 0x801BC0F8
 * EN v1.0 Size: 1940b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bc0f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 extraout_f1;
  double dVar6;
  double in_f29;
  double in_f30;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar9 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar5 = *(int *)(iVar4 + 0x40c);
  if ((*(int *)(iVar5 + 0xb0) == 0) ||
     (*(int *)(iVar5 + 0xb0) = *(int *)(iVar5 + 0xb0) + -1, 0 < *(int *)(iVar5 + 0xb0))) {
    if (*(char *)(iVar5 + 0xb6) < '\0') {
      uVar9 = FUN_80008cbc(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                           0xdb,0,param_13,param_14,param_15,param_16);
      FUN_80008cbc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0xdc,0,param_13
                   ,param_14,param_15,param_16);
      FUN_8008999c(7,1,0);
      FUN_80089734((double)FLOAT_803e58e4,(double)FLOAT_803e58e8,(double)FLOAT_803e58ec,7);
      FUN_8008986c(7,0xa0,0xa0,0xff,0x7f,0x28);
      *(byte *)(iVar5 + 0xb6) = *(byte *)(iVar5 + 0xb6) & 0x7f;
    }
    if ((*(uint *)(iVar4 + 0x314) & 4) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffffb;
      FUN_8000bb38(uVar1,(ushort)DAT_803266f8);
      DAT_803de800 = DAT_803de800 | 0x204;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 2) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffffd;
      FUN_8000bb38(uVar1,(ushort)DAT_803266fc);
      DAT_803de800 = DAT_803de800 | 0x404;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 0x10) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xffffffef;
      FUN_8000bb38(uVar1,(ushort)DAT_80326700);
      DAT_803de800 = DAT_803de800 | 0x804;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((*(uint *)(iVar4 + 0x314) & 8) != 0) {
      *(uint *)(iVar4 + 0x314) = *(uint *)(iVar4 + 0x314) & 0xfffffff7;
      FUN_8000bb38(uVar1,(ushort)DAT_80326704);
      DAT_803de800 = DAT_803de800 | 0x1004;
      FUN_80014acc((double)FLOAT_803e5890);
    }
    if ((DAT_803de800 & 0x2000) != 0) {
      iVar3 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b1,iVar5 + 0x4c,0x200001,0xffffffff,0);
        iVar3 = iVar3 + 1;
      } while (iVar3 < 0x32);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b2,iVar5 + 0x4c,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b3,iVar5 + 0x4c,0x200001,0xffffffff,0);
    }
    if ((DAT_803de800 & 0x80000) != 0) {
      (**(code **)(*DAT_803dd734 + 0xc))(uVar1,0x800,0,1,0);
    }
    if (((DAT_803de800 & 0x8020) != 0) || (*(char *)(iVar4 + 0x354) < '\x02')) {
      if ((DAT_803de800 & 0x20) == 0) {
        uVar2 = FUN_80022264(0,(int)*(char *)(iVar4 + 0x354));
        if ((uVar2 == 0) && (*(short *)(iVar4 + 0x402) == 2)) {
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b4,iVar5 + 0x34,0x200001,0xffffffff,0);
        }
      }
      else {
        iVar4 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b4,iVar5 + 0x34,0x200001,0xffffffff,0);
          iVar4 = iVar4 + 1;
        } while (iVar4 < 7);
      }
      if ((DAT_803de800 & 0x8000) != 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b2,iVar5 + 0x34,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b3,iVar5 + 0x34,0x200001,0xffffffff,0);
      }
    }
    if ((DAT_803de800 & 0x101c0) != 0) {
      if ((DAT_803de800 & 0x40) != 0) {
        iVar4 = 0;
        dVar7 = (double)FLOAT_803e58f0;
        dVar8 = (double)FLOAT_803e58f4;
        dVar6 = DOUBLE_803e5878;
        do {
          uStack_64 = FUN_80022264(0xfffffffb,5);
          uStack_64 = uStack_64 ^ 0x80000000;
          local_68 = 0x43300000;
          local_78 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_64) - dVar6)
                            );
          uStack_5c = FUN_80022264(0xfffffffb,5);
          uStack_5c = uStack_5c ^ 0x80000000;
          local_60 = 0x43300000;
          local_74 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar6)
                            );
          uStack_54 = FUN_80022264(2,8);
          uStack_54 = uStack_54 ^ 0x80000000;
          local_58 = 0x43300000;
          local_70 = (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar6)
                            );
          FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
          (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b5,iVar5 + 0x1c,0x200001,0xffffffff,&local_78);
          iVar4 = iVar4 + 1;
        } while (iVar4 < 5);
      }
      if ((DAT_803de800 & 0x80) != 0) {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b5,iVar5 + 4,0x200001,0xffffffff,0);
      }
      if ((DAT_803de800 & 0x100) != 0) {
        local_78 = FLOAT_803e58f0;
        local_74 = FLOAT_803e58f8;
        uStack_54 = FUN_80022264(4,8);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_70 = FLOAT_803e58fc *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e5878);
        FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b6,iVar5 + 4,0x200001,0xffffffff,&local_78);
      }
      if ((DAT_803de800 & 0x10000) != 0) {
        local_78 = FLOAT_803e5870;
        local_74 = FLOAT_803e58f8;
        local_70 = FLOAT_803e5900;
        FUN_80247bf8((float *)(iVar5 + 100),&local_78,&local_78);
        FUN_80003494(iVar5 + 0x94,(uint)&local_78,0xc);
        DAT_803de800 = DAT_803de800 | 0x20000;
      }
    }
    if ((DAT_803de800 & 0x4000) != 0) {
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x4b7,0,1,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x32);
    }
    if ((DAT_803de800 & 1) != 0) {
      FUN_8000faf8();
      FUN_80014acc((double)FLOAT_803e5890);
      FUN_8000e670((double)FLOAT_803e585c,(double)FLOAT_803e5860,(double)FLOAT_803e5864);
    }
    if ((DAT_803de800 & 0x40000) != 0) {
      FUN_8000faf8();
      FUN_80014acc((double)FLOAT_803e5904);
      FUN_8000e670((double)FLOAT_803e5860,(double)FLOAT_803e588c,(double)FLOAT_803e5890);
    }
    if ((DAT_803de800 & 2) != 0) {
      FUN_8000faf8();
      dVar6 = (double)FLOAT_803e5870;
      FUN_8000e670(dVar6,dVar6,dVar6);
      FUN_8000e69c((double)FLOAT_803e5870);
    }
    if ((DAT_803de800 & 4) == 0) {
      FUN_800201ac(0x25e,0);
    }
    else {
      FUN_800201ac(0x25e,1);
    }
    DAT_803de800 = DAT_803de800 & 0xa1ff0;
  }
  else {
    *(undefined4 *)(iVar5 + 0xb0) = 0;
    uVar9 = FUN_8012e0b8('\0');
    FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x77,'\x01',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bc88c
 * EN v1.0 Address: 0x801BC88C
 * EN v1.0 Size: 1292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bc88c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 in_r7;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  undefined8 uVar8;
  int local_40;
  uint uStack_3c;
  int local_38;
  undefined4 local_34;
  int local_30;
  int local_2c;
  undefined4 local_28;
  
  uVar8 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar6 = (int)uVar8;
  iVar7 = *(int *)(uVar3 + 0xb8);
  FUN_8002bac4();
  bVar1 = false;
  local_34 = DAT_802c2ac8;
  local_30 = DAT_802c2acc;
  local_2c = DAT_802c2ad0;
  local_28 = DAT_802c2ad4;
  if (DAT_803de80c != 0) {
    DAT_803de80c = DAT_803de80c + -1;
  }
  iVar4 = FUN_80036974(uVar3,&local_40,&local_38,&uStack_3c);
  if (iVar4 != 0) {
    uVar2 = DAT_803de800 & 0xffffffbf;
    if (*(short *)(iVar7 + 0x402) == 1) {
      if (((DAT_803de800 & 8) == 0) || (local_38 != 2)) {
        bVar1 = true;
      }
    }
    else if ((*(short *)(iVar7 + 0x402) == 2) &&
            (((local_38 != 4 || (*(float *)(uVar3 + 0x98) < FLOAT_803e58a8)) ||
             (*(short *)(uVar3 + 0xa0) != 0x12)))) {
      bVar1 = true;
    }
    DAT_803de800 = uVar2;
    if (bVar1) {
      if (DAT_803de80c == 0) {
        FUN_8000bb38(uVar3,0x4b2);
        iVar6 = *(int *)(*(int *)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4) + 0x50) +
                local_38 * 0x10;
        DAT_803ad600 = FLOAT_803dda58 + *(float *)(iVar6 + 4);
        DAT_803ad604 = *(float *)(iVar6 + 8);
        DAT_803ad608 = FLOAT_803dda5c + *(float *)(iVar6 + 0xc);
        (**(code **)(*DAT_803dd708 + 8))(uVar3,0x328,&DAT_803ad5f4,0x200001,0xffffffff,0);
        DAT_803ad600 = DAT_803ad600 - *(float *)(uVar3 + 0x18);
        DAT_803ad604 = DAT_803ad604 - *(float *)(uVar3 + 0x1c);
        DAT_803ad608 = DAT_803ad608 - *(float *)(uVar3 + 0x20);
        DAT_803ad5fc = FLOAT_803e58dc;
        DAT_803ad5f4 = 0;
        DAT_803ad5f6 = 0;
        DAT_803ad5f8 = 0;
        uVar2 = FUN_80022264(0,0x9b);
        local_30 = local_30 + uVar2;
        uVar2 = FUN_80022264(0,0x9b);
        local_2c = local_2c + uVar2;
        (**(code **)(*DAT_803de808 + 4))(uVar3,0,&DAT_803ad5f4,1,0xffffffff,&local_34);
        DAT_803de80c = 0x1e;
      }
    }
    else {
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        iVar5 = FUN_8002bac4();
        uVar2 = FUN_80296164(iVar5,1);
        if (uVar2 != 0) {
          in_r7 = 0;
          in_r8 = 2;
          in_r9 = 10;
          in_r10 = 0xffffffff;
          (**(code **)(*DAT_803dd738 + 0x28))
                    (uVar3,iVar6,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4));
          *(int *)(iVar6 + 0x2d0) = iVar5;
          *(undefined *)(iVar6 + 0x349) = 0;
        }
      }
      if (*(short *)(iVar7 + 0x402) == 1) {
        if (*(char *)(iVar6 + 0x354) == '\x03') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x68,0,0);
        }
        else if (*(char *)(iVar6 + 0x354) == '\x02') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x6c,0,0);
        }
      }
      else if (*(short *)(iVar7 + 0x402) == 2) {
        if (*(char *)(iVar6 + 0x354) == '\x03') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x77,0,0);
        }
        else if (*(char *)(iVar6 + 0x354) == '\x02') {
          in_r7 = 0;
          in_r8 = *DAT_803dd6f4;
          (**(code **)(in_r8 + 4))(uVar3,0x78,0,0);
        }
      }
      *(undefined *)(iVar6 + 0x346) = 0;
      *(char *)(iVar6 + 0x34f) = (char)iVar4;
      *(char *)(iVar6 + 0x354) = *(char *)(iVar6 + 0x354) + -1;
      FUN_8000bb38(uVar3,0x4b1);
      if (*(char *)(iVar6 + 0x354) < '\x01') {
        *(undefined *)(iVar6 + 0x354) = 0;
        *(undefined *)(iVar6 + 0x349) = 0;
        (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,0);
        *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(uVar3 + 0x54) + 0x60) & 0xfffe;
        *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) | 8;
        *(byte *)(uVar3 + 0xaf) = *(byte *)(uVar3 + 0xaf) & 0x7f;
        uVar8 = FUN_800201ac(0x20e,1);
        if (*(short *)(iVar7 + 0x402) == 1) {
          uVar8 = FUN_800201ac(0x20b,1);
        }
        else if (*(short *)(iVar7 + 0x402) == 2) {
          uVar8 = FUN_800201ac(0x266,1);
        }
      }
      else if (*(short *)(iVar7 + 0x402) == 1) {
        uVar8 = (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,10);
      }
      else {
        uVar8 = (**(code **)(*DAT_803dd70c + 0x14))(uVar3,iVar6,0xb);
      }
      FUN_800379bc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_40,0xe0001,
                   uVar3,0,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801bcd98
 * EN v1.0 Address: 0x801BCD98
 * EN v1.0 Size: 848b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bcd98(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12)
{
}
