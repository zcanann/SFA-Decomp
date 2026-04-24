// Function: FUN_80112334
// Entry: 80112334
// Size: 1148 bytes

/* WARNING: Removing unreachable block (ram,0x80112790) */
/* WARNING: Removing unreachable block (ram,0x80112344) */

void FUN_80112334(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7)

{
  float fVar1;
  undefined2 *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  undefined4 *puVar7;
  double extraout_f1;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  undefined8 uVar9;
  undefined local_48 [4];
  undefined4 local_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar9 = FUN_80286834();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_44 = DAT_803e28a8;
  local_48[0] = 1;
  param_3[0x103] = param_3 + 0x104;
  *(undefined2 *)((int)param_3 + 0x402) = 0;
  dVar8 = extraout_f1;
  if (((param_7 & 1) == 0) && ((param_7 & 0x20) == 0)) {
    FUN_800372f8((int)puVar2,3);
    FUN_80037a5c((int)puVar2,4);
  }
  (**(code **)(*DAT_803dd70c + 4))(puVar2,param_3,param_4,param_5);
  *param_3 = 0;
  *(undefined *)((int)param_3 + 0x349) = 0;
  fVar1 = FLOAT_803e28ac;
  param_3[0xa0] = FLOAT_803e28ac;
  param_3[0xa1] = fVar1;
  if (*(char *)(iVar5 + 0x32) == '\0') {
    *(undefined *)(param_3 + 0xd5) = 6;
  }
  else {
    *(char *)(param_3 + 0xd5) = *(char *)(iVar5 + 0x32);
  }
  *(undefined2 *)(param_3 + 0xfd) = *(undefined2 *)(iVar5 + 0x30);
  *(undefined2 *)((int)param_3 + 0x3f6) = *(undefined2 *)(iVar5 + 0x1a);
  *(undefined2 *)(param_3 + 0xfe) = *(undefined2 *)(iVar5 + 0x1c);
  if ((int)*(short *)(param_3 + 0xfd) != 0xffffffff) {
    FUN_800201ac((int)*(short *)(param_3 + 0xfd),0);
  }
  puVar7 = param_3 + 1;
  if ((param_7 & 2) == 0) {
    (**(code **)(*DAT_803dd728 + 4))(puVar7,0,0,0);
  }
  else {
    (**(code **)(*DAT_803dd728 + 4))(puVar7,0,param_6 | 0x200000,1);
  }
  (**(code **)(*DAT_803dd728 + 8))(puVar7,1,&DAT_8031aca4,&DAT_803dc640,4);
  if ((param_7 & 4) != 0) {
    (**(code **)(*DAT_803dd728 + 0xc))(puVar7,1,&DAT_8031ac98,&DAT_803de258,local_48);
  }
  (**(code **)(*DAT_803dd728 + 0x20))(puVar2,puVar7);
  *(undefined *)(param_3 + 0x101) = *(undefined *)(iVar5 + 0x2b);
  *(undefined2 *)(param_3 + 0xfc) = *(undefined2 *)(iVar5 + 0x22);
  *(undefined *)((int)param_3 + 0x406) = *(undefined *)(iVar5 + 0x2f);
  *(undefined *)((int)param_3 + 0x407) = *(undefined *)(iVar5 + 0x27);
  *(undefined *)(param_3 + 0x102) = *(undefined *)(iVar5 + 0x28);
  puVar2[0x58] = puVar2[0x58] | (short)*(char *)(param_3 + 0x102) & 7U;
  if ((param_7 & 8) == 0) {
    *(undefined2 *)((int)param_3 + 0x3fa) = 0;
    *(undefined2 *)(param_3 + 0xff) = 0;
  }
  else {
    *(undefined2 *)((int)param_3 + 0x3fa) = *(undefined2 *)(iVar5 + 0x20);
    *(undefined2 *)(param_3 + 0xff) = *(undefined2 *)(iVar5 + 0x1e);
  }
  *(undefined2 *)(param_3 + 0x100) = 0;
  *(ushort *)((int)param_3 + 0x3fe) = (ushort)*(byte *)(iVar5 + 0x29) << 3;
  *(undefined *)((int)param_3 + 0x405) = 0;
  param_3[0xf9] = (float)dVar8;
  *puVar2 = (short)((int)*(char *)(iVar5 + 0x2a) << 8);
  *(undefined *)(puVar2 + 0x1b) = 0xff;
  *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
  *(undefined2 *)((int)param_3 + 0x3f2) = *(undefined2 *)(iVar5 + 0x18);
  uVar3 = (uint)*(short *)((int)param_3 + 0x3f2);
  if (uVar3 == 0xffffffff) {
    *(undefined4 *)(puVar2 + 0x7a) = 0;
  }
  else if (puVar2[0x23] == 0x27c) {
    uVar3 = FUN_80020078(uVar3);
    uVar3 = countLeadingZeros(uVar3);
    *(uint *)(puVar2 + 0x7a) = uVar3 >> 5;
  }
  else {
    uVar3 = FUN_80020078(uVar3);
    *(uint *)(puVar2 + 0x7a) = uVar3;
  }
  iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar5 + 0x14));
  if (iVar4 == 0) {
    *(undefined4 *)(puVar2 + 0x7a) = 1;
  }
  if (*(int *)(puVar2 + 0x7a) == 0) {
    puVar2[3] = puVar2[3] & 0xbfff;
    FUN_80036018((int)puVar2);
    if (*(char *)(iVar5 + 0x2e) == -1) {
      *(undefined4 *)(puVar2 + 0x7c) = 1;
    }
    else {
      *(undefined4 *)(puVar2 + 0x7c) = 0;
    }
    if (((param_7 & 1) == 0) && ((param_7 & 0x20) == 0)) {
      FUN_800128a8(param_3 + 0xe1);
      *(undefined *)((int)param_3 + 0x382) = 4;
      *(undefined *)((int)param_3 + 899) = 0x14;
    }
    if ((param_7 & 0x10) == 0) {
      param_3[0xf7] = 0;
    }
    else {
      if ((param_3[0xf7] == 0) && ((param_7 & 0x20) == 0)) {
        iVar5 = FUN_80023d8c(0x108,0x1a);
        param_3[0xf7] = iVar5;
      }
      if (param_3[0xf7] != 0) {
        FUN_800033a8(param_3[0xf7],0,0x108);
      }
      uStack_3c = (uint)*(ushort *)((int)param_3 + 0x3fe);
      local_40 = 0x43300000;
      cVar6 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e28b8),
                         param_3[0xf7],puVar2,&local_44,0xffffffff);
      if (cVar6 == '\0') {
        *(ushort *)(param_3 + 0x100) = *(ushort *)(param_3 + 0x100) | 8;
      }
    }
  }
  else {
    FUN_80035ff8((int)puVar2);
    puVar2[3] = puVar2[3] | 0x4000;
  }
  FUN_80286880();
  return;
}

