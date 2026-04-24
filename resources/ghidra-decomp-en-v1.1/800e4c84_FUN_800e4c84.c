// Function: FUN_800e4c84
// Entry: 800e4c84
// Size: 480 bytes

/* WARNING: Removing unreachable block (ram,0x800e4e40) */
/* WARNING: Removing unreachable block (ram,0x800e4e38) */
/* WARNING: Removing unreachable block (ram,0x800e4e30) */
/* WARNING: Removing unreachable block (ram,0x800e4ca4) */
/* WARNING: Removing unreachable block (ram,0x800e4c9c) */
/* WARNING: Removing unreachable block (ram,0x800e4c94) */

int FUN_800e4c84(double param_1,double param_2,double param_3,int param_4,int param_5)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float local_78 [2];
  int local_70 [2];
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float local_50;
  float local_4c;
  float local_48;
  
  local_70[1] = -1;
  local_70[0] = -1;
  local_78[1] = FLOAT_803e12b8;
  local_78[0] = FLOAT_803e12b8;
  local_68 = *(float *)(param_4 + 8);
  local_64 = *(undefined4 *)(param_4 + 0xc);
  local_60 = *(undefined4 *)(param_4 + 0x10);
  iVar7 = 0;
  do {
    uVar6 = *(uint *)(param_4 + 0x1c);
    if (-1 < (int)uVar6) {
      if ((int)uVar6 < 0) {
        iVar5 = 0;
      }
      else {
        iVar4 = DAT_803de0f0 + -1;
        iVar3 = 0;
        while (iVar3 <= iVar4) {
          iVar2 = iVar4 + iVar3 >> 1;
          iVar5 = (&DAT_803a2448)[iVar2];
          if (*(uint *)(iVar5 + 0x14) < uVar6) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)(iVar5 + 0x14) <= uVar6) goto LAB_800e4d74;
            iVar4 = iVar2 + -1;
          }
        }
        iVar5 = 0;
      }
LAB_800e4d74:
      if (iVar5 != 0) {
        local_5c = *(undefined4 *)(iVar5 + 8);
        local_58 = *(undefined4 *)(iVar5 + 0xc);
        local_54 = *(undefined4 *)(iVar5 + 0x10);
        FUN_800e4e68(param_1,param_2,param_3,&local_68);
        fVar1 = (float)((double)local_48 - param_3) * (float)((double)local_48 - param_3) +
                (float)((double)local_50 - param_1) * (float)((double)local_50 - param_1) +
                (float)((double)local_4c - param_2) * (float)((double)local_4c - param_2);
        uVar6 = countLeadingZeros(param_5 - uVar6);
        uVar6 = uVar6 >> 5;
        if (local_78[uVar6] < fVar1) {
          local_78[uVar6] = fVar1;
          local_70[uVar6] = *(int *)(param_4 + 0x1c);
        }
      }
    }
    param_4 = param_4 + 4;
    iVar7 = iVar7 + 1;
    if (3 < iVar7) {
      if ((local_70[0] == -1) && (local_70[0] = local_70[1], local_70[1] == -1)) {
        local_70[0] = -1;
      }
      return local_70[0];
    }
  } while( true );
}

