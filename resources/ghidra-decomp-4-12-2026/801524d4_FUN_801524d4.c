// Function: FUN_801524d4
// Entry: 801524d4
// Size: 696 bytes

void FUN_801524d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  ushort uVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if ((*(char *)(param_10 + 0x33a) == '\x02') &&
     (uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c)), uVar2 == 0)) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
      FUN_8011f6d0(7);
    }
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_801520fc(param_9,param_10);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) &&
     (*(int *)(&DAT_8031fee4 + (uint)*(byte *)(param_10 + 0x33a) * 0xc) != 0)) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    uVar2 = (uint)*(byte *)(param_10 + 0x33a);
    if (uVar2 == 0) {
      if ((*(uint *)(param_10 + 0x2dc) & 0x20000000) != 0) {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c));
        if (uVar2 == 0) {
          *(undefined *)(param_10 + 0x33a) =
               (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
        }
        else {
          *(undefined *)(param_10 + 0x33a) =
               (&DAT_8031feea)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
        }
      }
    }
    else if (uVar2 == 2) {
      uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c));
      if ((uVar2 != 0) || ((*(uint *)(param_10 + 0x2dc) & 0x20000000) == 0)) {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
    }
    else if (uVar2 == 3) {
      uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c));
      if (uVar2 == 0) {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
      else {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031feea)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
    }
    else {
      *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[uVar2 * 0xc];
    }
    uVar1 = (ushort)(byte)(&DAT_8031fee8)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
    if (*(ushort *)(param_9 + 0xa0) != uVar1) {
      if ((uVar1 != 0) && (uVar1 != 4)) {
        FUN_8000bb38(param_9,0x4a8);
      }
      iVar3 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      FUN_8014d504((double)*(float *)(&DAT_8031fee0 + iVar3),param_2,param_3,param_4,param_5,param_6
                   ,param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_8031fee8)[iVar3],0,0xf,in_r8,
                   in_r9,in_r10);
    }
  }
  if ((&DAT_8031feeb)[(uint)*(byte *)(param_10 + 0x33a) * 0xc] != '\0') {
    FUN_8015224c(param_9,param_10);
  }
  return;
}

