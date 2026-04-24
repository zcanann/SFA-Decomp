// Function: FUN_802af410
// Entry: 802af410
// Size: 1000 bytes

void FUN_802af410(short *param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  bool bVar3;
  short *psVar4;
  int iVar5;
  undefined2 local_18 [6];
  
  bVar1 = (*(ushort *)(param_2 + 0x6e2) & 0x800) != 0;
  if (bVar1) {
    psVar4 = param_1;
    if (bVar1) {
      psVar4 = (short *)FUN_8011f3a8(local_18);
    }
    if (psVar4 == (short *)0x1) {
      FUN_80014b3c(0,0x800);
      *(ushort *)(param_2 + 0x6e2) = *(ushort *)(param_2 + 0x6e2) & 0xf7ff;
      *(undefined2 *)(param_2 + 0x80c) = local_18[0];
    }
  }
  if (((*(short *)(param_2 + 0x80c) == -1) ||
      (*(short *)(param_2 + 0x80c) == *(short *)(param_2 + 0x80a))) ||
     (iVar5 = FUN_80080204(), iVar5 != 0)) goto LAB_802af7d4;
  bVar1 = false;
  sVar2 = *(short *)(param_2 + 0x80c);
  if (sVar2 == 0x5bd) {
    iVar5 = FUN_802a98fc(param_1,param_2);
    if (iVar5 == 0) {
      bVar1 = true;
    }
    else {
      FUN_802ab38c(param_1,param_2,(int)*(short *)(param_2 + 0x80c));
    }
  }
  else if (sVar2 < 0x5bd) {
    if (sVar2 == 0x40) {
      if (((*(int *)(param_2 + 0x2d0) == 0) &&
          (9 < *(short *)(*(int *)(*(int *)(param_1 + 0x5c) + 0x35c) + 4))) &&
         ((*(byte *)(*(int *)(param_1 + 0x5c) + 0x3f3) >> 3 & 1) == 0)) {
        if ((*(short *)(param_2 + 0x274) == 1) || (*(short *)(param_2 + 0x274) == 2)) {
          bVar3 = true;
        }
        else {
          bVar3 = false;
        }
      }
      else {
        bVar3 = false;
      }
      if ((bVar3) && ((*(byte *)(param_2 + 0x3f3) >> 3 & 1) == 0)) {
        FUN_802ab38c(param_1,param_2);
      }
      else {
        bVar1 = true;
      }
    }
    else {
      if (sVar2 < 0x40) {
        if (sVar2 == 0x2d) goto LAB_802af504;
      }
      else if (sVar2 == 0x107) {
LAB_802af6c8:
        iVar5 = FUN_802a9a0c(param_1,param_2);
        if (iVar5 == 0) {
          bVar1 = true;
        }
        else {
          FUN_802ab38c(param_1,param_2,(int)*(short *)(param_2 + 0x80c));
        }
        goto LAB_802af7bc;
      }
LAB_802af7b0:
      FUN_802ab38c(param_1,param_2);
    }
  }
  else {
    if (sVar2 != 0x958) {
      if (sVar2 < 0x958) {
        if (sVar2 == 0x5ce) goto LAB_802af504;
        if ((0x5cd < sVar2) && (0x956 < sVar2)) {
          iVar5 = FUN_802a97d0(param_1,param_2);
          if (iVar5 == 0) {
            bVar1 = true;
          }
          else {
            FUN_802ab38c(param_1,param_2,(int)*(short *)(param_2 + 0x80c));
          }
          goto LAB_802af7bc;
        }
      }
      else if (sVar2 == 0xc55) goto LAB_802af6c8;
      goto LAB_802af7b0;
    }
LAB_802af504:
    iVar5 = FUN_802a9b1c(param_1,param_2);
    if (iVar5 == 0) {
      bVar1 = true;
    }
    else if (((*(int *)(param_2 + 0x2d0) == 0) && (*(char *)(param_2 + 0x8c8) != 'I')) &&
            ((*(char *)(param_2 + 0x8c8) != 'R' ||
             ((((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0 ||
               ((*(byte *)(param_2 + 0x3f1) >> 4 & 1) != 0)) ||
              (*(short *)(param_2 + 0x274) == 0x1d)))))) {
      if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
        sVar2 = *param_1;
        *(short *)(param_2 + 0x484) = sVar2;
        *(short *)(param_2 + 0x478) = sVar2;
        *(int *)(param_2 + 0x494) = (int)sVar2;
        *(float *)(param_2 + 0x284) = FLOAT_803e7ea4;
      }
      *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xdf;
      if ((((*(byte *)(param_2 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(param_2 + 0x8c8) != 'H')) &&
         ((*(char *)(param_2 + 0x8c8) != 'G' && (iVar5 = FUN_80080204(), iVar5 == 0)))) {
        (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
        *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xef;
      }
      FUN_80101974(2);
      (**(code **)(*DAT_803dca50 + 0x1c))(0x52,1,0,0,0,0x2d,0xff);
      *(byte *)(param_2 + 0x3f6) = *(byte *)(param_2 + 0x3f6) & 0xbf | 0x40;
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0x2a);
      *(code **)(param_2 + 0x304) = FUN_8029a4a8;
      FUN_802ab38c(param_1,param_2,(int)*(short *)(param_2 + 0x80c));
    }
  }
LAB_802af7bc:
  if (bVar1) {
    FUN_8000bb18(0,0x10a);
  }
LAB_802af7d4:
  *(undefined2 *)(param_2 + 0x80c) = 0xffff;
  return;
}

