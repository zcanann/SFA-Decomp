// Function: FUN_801b4398
// Entry: 801b4398
// Size: 724 bytes

/* WARNING: Removing unreachable block (ram,0x801b464c) */
/* WARNING: Removing unreachable block (ram,0x801b43a8) */

void FUN_801b4398(undefined8 param_1,double param_2,double param_3,double param_4)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  undefined extraout_r4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  
  uVar4 = FUN_8028683c();
  iVar5 = *(int *)(uVar4 + 0x4c);
  iVar6 = *(int *)(uVar4 + 0xb8);
  bVar1 = *(byte *)(iVar6 + 0xa58);
  *(byte *)(iVar6 + 0xa58) = bVar1 + 1;
  iVar7 = (uint)bVar1 * 0x30;
  *(float *)(iVar6 + iVar7) = (float)param_2;
  iVar8 = iVar6 + iVar7;
  *(float *)(iVar8 + 4) = (float)param_3;
  *(float *)(iVar8 + 8) = (float)param_4;
  *(float *)(iVar8 + 0x18) = FLOAT_803e55c4;
  *(undefined4 *)(iVar8 + 0xc) = *(undefined4 *)(iVar6 + 0x18);
  *(float *)(iVar8 + 0x1c) = (float)extraout_f1;
  *(undefined *)(iVar8 + 0x2d) = extraout_r4;
  *(undefined4 *)(iVar8 + 0x10) = 0;
  dVar9 = FUN_80293900(extraout_f1);
  *(int *)(iVar8 + 0x14) = (int)((double)FLOAT_803e55c8 * dVar9);
  iVar3 = *(int *)(iVar8 + 0x14);
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0x3c < iVar3) {
    iVar3 = 0x3c;
  }
  *(int *)(iVar8 + 0x14) = iVar3;
  if ((*(char *)(iVar8 + 0x2d) != '\0') || (cVar2 = *(char *)(iVar5 + 0x19), cVar2 == '\0'))
  goto LAB_801b44d4;
  if (cVar2 == '\x02') {
    FUN_8000bb38(uVar4,0x4bf);
    goto LAB_801b44d4;
  }
  if (cVar2 == '\x03') {
    FUN_8000bb38(uVar4,0x4c2);
    goto LAB_801b44d4;
  }
  cVar2 = *(char *)(uVar4 + 0xac);
  if (cVar2 < ':') {
    if (cVar2 == ',') {
LAB_801b44b4:
      FUN_8000b4f0(uVar4,0x4b8,2);
      goto LAB_801b44d4;
    }
  }
  else if (cVar2 < '?') goto LAB_801b44b4;
  FUN_8000bb38(uVar4,0x203);
LAB_801b44d4:
  uVar4 = FUN_80022264(0,0xffff);
  *(short *)(iVar6 + iVar7 + 0x28) = (short)uVar4;
  uVar4 = FUN_80022264(200,300);
  iVar3 = iVar6 + iVar7;
  *(short *)(iVar3 + 0x2a) = (short)uVar4;
  uVar4 = FUN_80022264(0,1);
  if (uVar4 != 0) {
    *(short *)(iVar3 + 0x2a) = -*(short *)(iVar3 + 0x2a);
  }
  uVar4 = FUN_80022264(0,3);
  *(char *)(iVar6 + iVar7 + 0x2c) = (char)uVar4;
  dVar10 = (double)*(float *)(iVar8 + 0x1c);
  dVar9 = (double)FUN_80292538();
  *(float *)(iVar8 + 0xc) =
       -(float)((double)FLOAT_803de7f0 *
                (double)(float)((double)(float)(dVar10 - (double)*(float *)(iVar8 + 0x18)) * dVar9)
               - dVar10);
  dVar9 = (double)FUN_80292538();
  iVar6 = iVar6 + iVar7;
  *(char *)(iVar6 + 0x2e) =
       (char)(int)-(float)((double)FLOAT_803de7ec * (double)(float)((double)FLOAT_803e55d0 * dVar9)
                          - (double)FLOAT_803e55d0);
  *(int *)(iVar6 + 0x20) = (int)FLOAT_803e55d8;
  *(undefined4 *)(iVar6 + 0x24) = *(undefined4 *)(iVar6 + 0x20);
  *(undefined *)(iVar6 + 0x2f) = 1;
  FUN_80286888();
  return;
}

