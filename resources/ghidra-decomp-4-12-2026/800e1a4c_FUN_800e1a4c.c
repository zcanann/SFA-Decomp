// Function: FUN_800e1a4c
// Entry: 800e1a4c
// Size: 856 bytes

/* WARNING: Removing unreachable block (ram,0x800e1d84) */
/* WARNING: Removing unreachable block (ram,0x800e1d7c) */
/* WARNING: Removing unreachable block (ram,0x800e1d74) */
/* WARNING: Removing unreachable block (ram,0x800e1a6c) */
/* WARNING: Removing unreachable block (ram,0x800e1a64) */
/* WARNING: Removing unreachable block (ram,0x800e1a5c) */

int FUN_800e1a4c(double param_1,double param_2,double param_3,int param_4,float *param_5)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  float local_78;
  float local_74;
  float local_70;
  uint local_6c [4];
  uint auStack_5c [8];
  
LAB_800e1c9c:
  do {
    while( true ) {
      bVar1 = false;
      if ((*(int *)(param_4 + 0x1c) == -1) || ((*(byte *)(param_4 + 0x1b) & 1) != 0)) {
        if ((*(int *)(param_4 + 0x20) == -1) || ((*(byte *)(param_4 + 0x1b) & 2) != 0)) {
          if ((*(int *)(param_4 + 0x24) == -1) || ((*(byte *)(param_4 + 0x1b) & 4) != 0)) {
            if ((*(int *)(param_4 + 0x28) == -1) || ((*(byte *)(param_4 + 0x1b) & 8) != 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) {
        *param_5 = FLOAT_803e12b8;
        return param_4;
      }
      FUN_800e4a48(param_4,(int *)auStack_5c);
      iVar2 = FUN_800e1da8(param_1,param_2,param_3,auStack_5c,&local_70,&local_74,&local_78);
      if ((((iVar2 != 0) && (FLOAT_803e12c8 < local_70)) && (local_70 < FLOAT_803e12cc)) &&
         ((FLOAT_803e12d0 < local_74 && (local_74 < FLOAT_803e12d4)))) {
        *param_5 = local_78;
        return param_4;
      }
      iVar2 = 0;
      uVar4 = *(uint *)(param_4 + 0x1c);
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 1) == 0)) && (uVar4 != 0)) {
        iVar2 = 1;
        local_6c[0] = uVar4;
      }
      uVar4 = *(uint *)(param_4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 2) == 0)) && (uVar4 != 0)) {
        iVar3 = iVar2 + 1;
        local_6c[iVar2] = uVar4;
      }
      uVar4 = *(uint *)(param_4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 4) == 0)) && (uVar4 != 0)) {
        iVar2 = iVar3 + 1;
        local_6c[iVar3] = uVar4;
      }
      uVar4 = *(uint *)(param_4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar4) && ((*(byte *)(param_4 + 0x1b) & 8) == 0)) && (uVar4 != 0)) {
        iVar3 = iVar2 + 1;
        local_6c[iVar2] = uVar4;
      }
      if (iVar3 == 0) {
        uVar4 = 0xffffffff;
      }
      else {
        uVar4 = FUN_80022264(0,iVar3 - 1);
        uVar4 = local_6c[uVar4];
      }
      if (-1 < (int)uVar4) break;
      param_4 = 0;
    }
    iVar3 = DAT_803de0f0 + -1;
    iVar2 = 0;
    while (iVar2 <= iVar3) {
      iVar5 = iVar3 + iVar2 >> 1;
      param_4 = (&DAT_803a2448)[iVar5];
      if (*(uint *)(param_4 + 0x14) < uVar4) {
        iVar2 = iVar5 + 1;
      }
      else {
        if (*(uint *)(param_4 + 0x14) <= uVar4) goto LAB_800e1c9c;
        iVar3 = iVar5 + -1;
      }
    }
    param_4 = 0;
  } while( true );
}

