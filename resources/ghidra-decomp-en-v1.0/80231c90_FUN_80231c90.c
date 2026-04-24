// Function: FUN_80231c90
// Entry: 80231c90
// Size: 416 bytes

void FUN_80231c90(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  double local_28;
  
  uVar6 = FUN_802860dc();
  iVar2 = (int)uVar6;
  iVar5 = *(int *)(iVar2 + 0x9c);
  if (*(char *)(iVar5 + 0x19) == '(') {
    iVar4 = 0;
    do {
      if (iVar4 == 0) {
        bVar1 = *(byte *)(iVar5 + 0x18);
        local_28 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar5 + 0x1a) ^ 0x80000000);
        local_28 = local_28 - DOUBLE_803e7178;
      }
      else {
        bVar1 = *(byte *)(iVar5 + 0x2f);
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x30));
        local_28 = local_28 - DOUBLE_803e7180;
      }
      if (bVar1 == 3) {
        *(float *)(iVar2 + 0x10c) = (float)local_28 * FLOAT_803e716c;
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          if (-1 < (char)*(byte *)(iVar2 + 0x160)) {
            *(byte *)(iVar2 + 0x160) = *(byte *)(iVar2 + 0x160) & 0x7f | 0x80;
            iVar3 = *(int *)((int)((ulonglong)uVar6 >> 0x20) + 0x4c);
            if (*(char *)(iVar2 + 0x15c) == '\x01') {
              *(byte *)(iVar2 + 0x160) = *(byte *)(iVar2 + 0x160) & 0xdf;
              FUN_8008016c(iVar2 + 0x124);
              FUN_80080178(iVar2 + 0x124,*(undefined *)(iVar3 + 0x2c));
            }
          }
        }
        else if (bVar1 != 0) {
          *(byte *)(iVar2 + 0x160) = *(byte *)(iVar2 + 0x160) & 0x7f;
        }
      }
      else if (bVar1 == 5) {
        *(byte *)(iVar2 + 0x160) = *(byte *)(iVar2 + 0x160) & 0xf7;
      }
      else if ((bVar1 < 5) && ((*(byte *)(iVar2 + 0x160) >> 3 & 1) == 0)) {
        *(byte *)(iVar2 + 0x160) = *(byte *)(iVar2 + 0x160) & 0xf7 | 8;
        *(short *)(iVar2 + 0x144) = (short)(int)(FLOAT_803e7170 * (float)local_28);
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 2);
  }
  FUN_80286128();
  return;
}

