// Function: FUN_801133d8
// Entry: 801133d8
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801134f4) */
/* WARNING: Removing unreachable block (ram,0x801133e8) */

void FUN_801133d8(undefined4 param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double extraout_f1;
  double in_f31;
  double dVar5;
  double in_ps31_1;
  undefined8 uVar6;
  undefined4 local_90;
  float local_8c;
  undefined4 local_88;
  int aiStack_84 [31];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_80286840();
  piVar1 = (int *)((ulonglong)uVar6 >> 0x20);
  iVar4 = (int)uVar6;
  dVar5 = extraout_f1;
  iVar2 = FUN_8002bac4();
  if ((((*(char *)(iVar4 + 0x346) != '\0') && (*(int *)(iVar4 + 0x2d0) == iVar2)) &&
      (*(char *)(iVar4 + 0x354) != '\0')) &&
     ((((double)*(float *)(iVar4 + 0x2c0) <= dVar5 || (param_3 == 0)) &&
      ((uVar3 = FUN_80296164(iVar2,1), uVar3 != 0 && (iVar4 = FUN_80297248(iVar2), 0 < iVar4)))))) {
    local_90 = *(undefined4 *)(iVar2 + 0xc);
    local_8c = FLOAT_803e28e8 + *(float *)(iVar2 + 0x10);
    local_88 = *(undefined4 *)(iVar2 + 0x14);
    FUN_80064248(piVar1 + 3,&local_90,(float *)0x0,aiStack_84,piVar1,4,0xffffffff,0,0);
  }
  FUN_8028688c();
  return;
}

