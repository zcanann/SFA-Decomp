// Function: FUN_801c0e60
// Entry: 801c0e60
// Size: 376 bytes

/* WARNING: Removing unreachable block (ram,0x801c0fb8) */

void FUN_801c0e60(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack88 [12];
  undefined auStack76 [12];
  float local_40;
  float local_3c;
  float local_38;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar1 = (int *)FUN_802860dc();
  iVar5 = *piVar1;
  dVar9 = (double)FLOAT_803e4dfc;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(piVar1 + 2); iVar3 = iVar3 + 1) {
    local_38 = (float)dVar9;
    local_3c = (float)dVar9;
    local_40 = (float)dVar9;
    if (*(char *)(iVar5 + 0x30) == '\0') {
      iVar6 = iVar5;
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar5 + 0x24); iVar4 = iVar4 + 1) {
        iVar2 = *(int *)(iVar6 + 0x28);
        if (iVar5 == *(int *)(iVar2 + 4)) {
          FUN_80247730(&local_40,iVar2 + 0x18,&local_40);
        }
        else {
          FUN_80247754(&local_40,iVar2 + 0x18,&local_40);
        }
        iVar6 = iVar6 + 4;
      }
      dVar8 = (double)FUN_802477f0(&local_40);
      if ((double)(float)piVar1[0xb] < dVar8) {
        FUN_80247778((double)(float)((double)(float)piVar1[0xb] / dVar8),&local_40,&local_40);
      }
      FUN_80247778((double)(float)piVar1[0x10],&local_40,&local_40);
      FUN_80247730(&local_40,iVar5 + 0x18,&local_40);
      FUN_80247730(iVar5 + 0xc,&local_40,iVar5 + 0xc);
      FUN_80247778((double)(float)piVar1[0xe],iVar5 + 0xc,auStack76);
      FUN_80247754(iVar5 + 0xc,auStack76,iVar5 + 0xc);
      *(float *)(iVar5 + 0x10) = (float)piVar1[0xc] * (float)piVar1[0xf] + *(float *)(iVar5 + 0x10);
      FUN_80247778((double)(float)piVar1[0xc],iVar5 + 0xc,auStack88);
      FUN_80247730(iVar5,auStack88,iVar5);
    }
    iVar5 = iVar5 + 0x34;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128();
  return;
}

