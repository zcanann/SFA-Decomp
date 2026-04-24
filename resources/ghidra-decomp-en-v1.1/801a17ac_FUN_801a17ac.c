// Function: FUN_801a17ac
// Entry: 801a17ac
// Size: 716 bytes

/* WARNING: Removing unreachable block (ram,0x801a1a58) */
/* WARNING: Removing unreachable block (ram,0x801a1a50) */
/* WARNING: Removing unreachable block (ram,0x801a1a48) */
/* WARNING: Removing unreachable block (ram,0x801a17cc) */
/* WARNING: Removing unreachable block (ram,0x801a17c4) */
/* WARNING: Removing unreachable block (ram,0x801a17bc) */

void FUN_801a17ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_58;
  undefined4 auStack_54 [11];
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
  uVar1 = FUN_80286838();
  iVar8 = *(int *)(uVar1 + 0xb8);
  iVar2 = FUN_80036974(uVar1,auStack_54,(int *)0x0,(uint *)0x0);
  if ((iVar2 != 0) ||
     ((*(char *)(*(int *)(uVar1 + 0x54) + 0xad) != '\0' && ((*(byte *)(iVar8 + 0x49) & 2) != 0)))) {
    *(char *)(iVar8 + 0x16) = *(char *)(iVar8 + 0x16) + '\x01';
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) | 1;
  }
  if (*(char *)(iVar8 + 0x16) != '\0') {
    if ((*(byte *)(iVar8 + 0x48) >> 6 & 1) != 0) {
      iVar6 = *(int *)(uVar1 + 0x4c);
      iVar2 = 0;
      if (*(short *)(iVar6 + 0x1a) == 0) {
        iVar2 = FUN_80036f50(0x3a,uVar1,(float *)0x0);
      }
      else {
        piVar3 = FUN_80037048(0x3a,&local_58);
        piVar5 = piVar3;
        for (iVar7 = 0; iVar7 < local_58; iVar7 = iVar7 + 1) {
          iVar4 = FUN_80221cc0(*piVar5);
          if (*(short *)(iVar6 + 0x1a) == iVar4) {
            iVar2 = piVar3[iVar7];
            break;
          }
          piVar5 = piVar5 + 1;
        }
      }
      if (iVar2 != 0) {
        dVar11 = (double)*(float *)(uVar1 + 0xc);
        dVar10 = (double)*(float *)(uVar1 + 0x10);
        dVar9 = (double)*(float *)(uVar1 + 0x14);
        *(undefined4 *)(uVar1 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
        *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
        *(undefined4 *)(uVar1 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
        FUN_800e85f4(uVar1);
        *(float *)(uVar1 + 0xc) = (float)dVar11;
        *(float *)(uVar1 + 0x10) = (float)dVar10;
        *(float *)(uVar1 + 0x14) = (float)dVar9;
      }
    }
    FUN_80035f54(uVar1,0x80);
    FUN_80035f40(uVar1,1);
    FUN_80035c48(uVar1,0x14,-5,0x14);
    FUN_80036018(uVar1);
    FUN_80035f84(uVar1);
    FUN_80035eec(uVar1,5,4,0);
    FUN_8000bb38(uVar1,0xd1);
    *(float *)(uVar1 + 0x10) = *(float *)(uVar1 + 0x10) + FLOAT_803e4fa0;
    FUN_8009adfc((double)FLOAT_803e4f58,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,1,1,0,0,0,1,0);
    if (*(char *)(iVar8 + 0x15) != '\0') {
      (**(code **)(*DAT_803dd740 + 0x30))(uVar1,iVar8);
      *(undefined *)(iVar8 + 0x15) = 0;
    }
    *(undefined *)(iVar8 + 0x17) = 1;
    *(byte *)(iVar8 + 0x4a) = *(byte *)(iVar8 + 0x4a) & 0xdf;
    FUN_8003709c(uVar1,0x19);
    if (*(int *)(uVar1 + 0x30) == 0) {
      *(float *)(iVar8 + 0x34) = FLOAT_803e4f5c;
    }
    else {
      *(float *)(iVar8 + 0x34) = FLOAT_803e4f5c;
    }
    iVar2 = FUN_8002ba84();
    if (iVar2 != 0) {
      FUN_80139280(iVar2);
    }
    *(byte *)(iVar8 + 0x49) = *(byte *)(iVar8 + 0x49) & 0xfd;
    if (*(int *)(iVar8 + 0x10) != 0) {
      FUN_80238c8c(*(int *)(iVar8 + 0x10));
    }
  }
  FUN_80286884();
  return;
}

