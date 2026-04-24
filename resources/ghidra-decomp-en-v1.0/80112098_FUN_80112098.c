// Function: FUN_80112098
// Entry: 80112098
// Size: 1148 bytes

/* WARNING: Removing unreachable block (ram,0x801124f4) */

void FUN_80112098(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 uVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 uVar9;
  double extraout_f1;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  undefined local_48 [4];
  undefined4 local_44;
  undefined4 local_40;
  uint uStack60;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860d0();
  puVar3 = (undefined2 *)((ulonglong)uVar11 >> 0x20);
  iVar7 = (int)uVar11;
  local_44 = DAT_803e1c28;
  local_48[0] = 1;
  param_3[0x103] = param_3 + 0x104;
  *(undefined2 *)((int)param_3 + 0x402) = 0;
  dVar10 = extraout_f1;
  if (((param_7 & 1) == 0) && ((param_7 & 0x20) == 0)) {
    FUN_80037200(puVar3,3);
    FUN_80037964(puVar3,4);
  }
  (**(code **)(*DAT_803dca8c + 4))(puVar3,param_3,param_4,param_5);
  *param_3 = 0;
  *(undefined *)((int)param_3 + 0x349) = 0;
  fVar1 = FLOAT_803e1c2c;
  param_3[0xa0] = FLOAT_803e1c2c;
  param_3[0xa1] = fVar1;
  if (*(char *)(iVar7 + 0x32) == '\0') {
    *(undefined *)(param_3 + 0xd5) = 6;
  }
  else {
    *(char *)(param_3 + 0xd5) = *(char *)(iVar7 + 0x32);
  }
  *(undefined2 *)(param_3 + 0xfd) = *(undefined2 *)(iVar7 + 0x30);
  *(undefined2 *)((int)param_3 + 0x3f6) = *(undefined2 *)(iVar7 + 0x1a);
  *(undefined2 *)(param_3 + 0xfe) = *(undefined2 *)(iVar7 + 0x1c);
  if (*(short *)(param_3 + 0xfd) != -1) {
    FUN_800200e8((int)*(short *)(param_3 + 0xfd),0);
  }
  puVar8 = param_3 + 1;
  if ((param_7 & 2) == 0) {
    (**(code **)(*DAT_803dcaa8 + 4))(puVar8,0,0,0);
  }
  else {
    (**(code **)(*DAT_803dcaa8 + 4))(puVar8,0,param_6 | 0x200000,1);
  }
  (**(code **)(*DAT_803dcaa8 + 8))(puVar8,1,&DAT_8031a054,&DAT_803db9e0,4);
  if ((param_7 & 4) != 0) {
    (**(code **)(*DAT_803dcaa8 + 0xc))(puVar8,1,&DAT_8031a048,&DAT_803dd5e0,local_48);
  }
  (**(code **)(*DAT_803dcaa8 + 0x20))(puVar3,puVar8);
  *(undefined *)(param_3 + 0x101) = *(undefined *)(iVar7 + 0x2b);
  *(undefined2 *)(param_3 + 0xfc) = *(undefined2 *)(iVar7 + 0x22);
  *(undefined *)((int)param_3 + 0x406) = *(undefined *)(iVar7 + 0x2f);
  *(undefined *)((int)param_3 + 0x407) = *(undefined *)(iVar7 + 0x27);
  *(undefined *)(param_3 + 0x102) = *(undefined *)(iVar7 + 0x28);
  puVar3[0x58] = puVar3[0x58] | (short)*(char *)(param_3 + 0x102) & 7U;
  if ((param_7 & 8) == 0) {
    *(undefined2 *)((int)param_3 + 0x3fa) = 0;
    *(undefined2 *)(param_3 + 0xff) = 0;
  }
  else {
    *(undefined2 *)((int)param_3 + 0x3fa) = *(undefined2 *)(iVar7 + 0x20);
    *(undefined2 *)(param_3 + 0xff) = *(undefined2 *)(iVar7 + 0x1e);
  }
  *(undefined2 *)(param_3 + 0x100) = 0;
  *(ushort *)((int)param_3 + 0x3fe) = (ushort)*(byte *)(iVar7 + 0x29) << 3;
  *(undefined *)((int)param_3 + 0x405) = 0;
  param_3[0xf9] = (float)dVar10;
  *puVar3 = (short)((int)*(char *)(iVar7 + 0x2a) << 8);
  *(undefined *)(puVar3 + 0x1b) = 0xff;
  *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
  *(undefined2 *)((int)param_3 + 0x3f2) = *(undefined2 *)(iVar7 + 0x18);
  if (*(short *)((int)param_3 + 0x3f2) == -1) {
    *(undefined4 *)(puVar3 + 0x7a) = 0;
  }
  else if (puVar3[0x23] == 0x27c) {
    uVar4 = FUN_8001ffb4();
    uVar2 = countLeadingZeros(uVar4);
    *(uint *)(puVar3 + 0x7a) = uVar2 >> 5;
  }
  else {
    uVar4 = FUN_8001ffb4();
    *(undefined4 *)(puVar3 + 0x7a) = uVar4;
  }
  iVar5 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar7 + 0x14));
  if (iVar5 == 0) {
    *(undefined4 *)(puVar3 + 0x7a) = 1;
  }
  if (*(int *)(puVar3 + 0x7a) == 0) {
    puVar3[3] = puVar3[3] & 0xbfff;
    FUN_80035f20(puVar3);
    if (*(char *)(iVar7 + 0x2e) == -1) {
      *(undefined4 *)(puVar3 + 0x7c) = 1;
    }
    else {
      *(undefined4 *)(puVar3 + 0x7c) = 0;
    }
    if (((param_7 & 1) == 0) && ((param_7 & 0x20) == 0)) {
      FUN_80012888(param_3 + 0xe1);
      *(undefined *)((int)param_3 + 0x382) = 4;
      *(undefined *)((int)param_3 + 899) = 0x14;
    }
    if ((param_7 & 0x10) == 0) {
      param_3[0xf7] = 0;
    }
    else {
      if ((param_3[0xf7] == 0) && ((param_7 & 0x20) == 0)) {
        uVar4 = FUN_80023cc8(0x108,0x1a,0);
        param_3[0xf7] = uVar4;
      }
      if (param_3[0xf7] != 0) {
        FUN_800033a8(param_3[0xf7],0,0x108);
      }
      uStack60 = (uint)*(ushort *)((int)param_3 + 0x3fe);
      local_40 = 0x43300000;
      cVar6 = (**(code **)(*DAT_803dca9c + 0x8c))
                        ((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e1c38),
                         param_3[0xf7],puVar3,&local_44,0xffffffff);
      if (cVar6 == '\0') {
        *(ushort *)(param_3 + 0x100) = *(ushort *)(param_3 + 0x100) | 8;
      }
    }
  }
  else {
    FUN_80035f00(puVar3);
    puVar3[3] = puVar3[3] | 0x4000;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_8028611c();
  return;
}

