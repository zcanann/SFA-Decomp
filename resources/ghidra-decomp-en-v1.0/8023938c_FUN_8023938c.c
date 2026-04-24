// Function: FUN_8023938c
// Entry: 8023938c
// Size: 332 bytes

/* WARNING: Removing unreachable block (ram,0x802393bc) */

undefined4 FUN_8023938c(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    bVar1 = *(byte *)(iVar3 + 0x1b);
    bVar2 = bVar1 >> 4;
    if (bVar2 == 2) {
      *(byte *)(iVar3 + 0x1b) = bVar1 & 0xf | 0x30;
      *(undefined *)(iVar3 + 0x18) = *(undefined *)(param_3 + iVar4 + 0x81);
    }
    else if (bVar2 < 2) {
      if (bVar2 == 0) {
        *(byte *)(iVar3 + 0x1b) = bVar1 & 0xf | 0x10;
        *(float *)(iVar3 + 8) =
             FLOAT_803e7440 *
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + iVar4 + 0x81)) -
                    DOUBLE_803e7448);
      }
      else {
        *(byte *)(iVar3 + 0x1b) = bVar1 & 0xf | 0x20;
        *(float *)(iVar3 + 0xc) =
             FLOAT_803e7440 *
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + iVar4 + 0x81)) -
                    DOUBLE_803e7448);
      }
    }
    else if (bVar2 == 4) {
      *(byte *)(iVar3 + 0x1b) = bVar1 & 0xf | 0x50;
      *(undefined *)(iVar3 + 0x1a) = *(undefined *)(param_3 + iVar4 + 0x81);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    }
    else if (bVar2 < 4) {
      *(byte *)(iVar3 + 0x1b) = bVar1 & 0xf | 0x40;
      *(undefined *)(iVar3 + 0x19) = *(undefined *)(param_3 + iVar4 + 0x81);
    }
    else {
      *(byte *)(iVar3 + 0x1b) = *(byte *)(iVar3 + 0x1b) & 0xf | 0xa0;
    }
  }
  return 0;
}

