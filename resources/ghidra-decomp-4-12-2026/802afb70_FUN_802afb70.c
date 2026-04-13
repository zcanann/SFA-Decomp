// Function: FUN_802afb70
// Entry: 802afb70
// Size: 1000 bytes

void FUN_802afb70(short *param_1,int param_2)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  short *psVar4;
  int iVar5;
  undefined2 local_18 [6];
  ushort uVar6;
  
  bVar3 = (*(ushort *)(param_2 + 0x6e2) & 0x800) != 0;
  if (bVar3) {
    psVar4 = param_1;
    if (bVar3) {
      uVar6 = FUN_8011f68c(local_18);
      psVar4 = (short *)(uint)uVar6;
    }
    if (psVar4 == (short *)0x1) {
      FUN_80014b68(0,0x800);
      *(ushort *)(param_2 + 0x6e2) = *(ushort *)(param_2 + 0x6e2) & 0xf7ff;
      *(undefined2 *)(param_2 + 0x80c) = local_18[0];
    }
  }
  if (((*(short *)(param_2 + 0x80c) == -1) ||
      (*(short *)(param_2 + 0x80c) == *(short *)(param_2 + 0x80a))) ||
     (iVar5 = FUN_80080490(), iVar5 != 0)) goto LAB_802aff34;
  bVar3 = false;
  iVar5 = (int)*(short *)(param_2 + 0x80c);
  if (iVar5 == 0x5bd) {
    iVar5 = FUN_802aa05c((int)param_1,param_2);
    if (iVar5 == 0) {
      bVar3 = true;
    }
    else {
      FUN_802abaec((uint)param_1,param_2,(int)*(short *)(param_2 + 0x80c));
    }
  }
  else if (iVar5 < 0x5bd) {
    if (iVar5 == 0x40) {
      if (((*(int *)(param_2 + 0x2d0) == 0) &&
          (9 < *(short *)(*(int *)(*(int *)(param_1 + 0x5c) + 0x35c) + 4))) &&
         ((*(byte *)(*(int *)(param_1 + 0x5c) + 0x3f3) >> 3 & 1) == 0)) {
        if ((*(short *)(param_2 + 0x274) == 1) || (*(short *)(param_2 + 0x274) == 2)) {
          bVar2 = true;
        }
        else {
          bVar2 = false;
        }
      }
      else {
        bVar2 = false;
      }
      if ((bVar2) && ((*(byte *)(param_2 + 0x3f3) >> 3 & 1) == 0)) {
        FUN_802abaec((uint)param_1,param_2,0x40);
      }
      else {
        bVar3 = true;
      }
    }
    else {
      if (iVar5 < 0x40) {
        if (iVar5 == 0x2d) goto LAB_802afc64;
      }
      else if (iVar5 == 0x107) {
LAB_802afe28:
        iVar5 = FUN_802aa16c((int)param_1,param_2);
        if (iVar5 == 0) {
          bVar3 = true;
        }
        else {
          FUN_802abaec((uint)param_1,param_2,(int)*(short *)(param_2 + 0x80c));
        }
        goto LAB_802aff1c;
      }
LAB_802aff10:
      FUN_802abaec((uint)param_1,param_2,iVar5);
    }
  }
  else {
    if (iVar5 != 0x958) {
      if (iVar5 < 0x958) {
        if (iVar5 == 0x5ce) goto LAB_802afc64;
        if ((0x5cd < iVar5) && (0x956 < iVar5)) {
          iVar5 = FUN_802a9f30((int)param_1,param_2);
          if (iVar5 == 0) {
            bVar3 = true;
          }
          else {
            FUN_802abaec((uint)param_1,param_2,(int)*(short *)(param_2 + 0x80c));
          }
          goto LAB_802aff1c;
        }
      }
      else if (iVar5 == 0xc55) goto LAB_802afe28;
      goto LAB_802aff10;
    }
LAB_802afc64:
    iVar5 = FUN_802aa27c((int)param_1,param_2,iVar5);
    if (iVar5 == 0) {
      bVar3 = true;
    }
    else if (((*(int *)(param_2 + 0x2d0) == 0) && (*(char *)(param_2 + 0x8c8) != 'I')) &&
            ((*(char *)(param_2 + 0x8c8) != 'R' ||
             ((((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0 ||
               ((*(byte *)(param_2 + 0x3f1) >> 4 & 1) != 0)) ||
              (*(short *)(param_2 + 0x274) == 0x1d)))))) {
      if ((*(byte *)(param_2 + 0x3f1) >> 5 & 1) != 0) {
        sVar1 = *param_1;
        *(short *)(param_2 + 0x484) = sVar1;
        *(short *)(param_2 + 0x478) = sVar1;
        *(int *)(param_2 + 0x494) = (int)sVar1;
        *(float *)(param_2 + 0x284) = FLOAT_803e8b3c;
      }
      *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xdf;
      if ((((*(byte *)(param_2 + 0x3f1) >> 4 & 1) != 0) && (*(char *)(param_2 + 0x8c8) != 'H')) &&
         ((*(char *)(param_2 + 0x8c8) != 'G' && (iVar5 = FUN_80080490(), iVar5 == 0)))) {
        (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
        *(byte *)(param_2 + 0x3f1) = *(byte *)(param_2 + 0x3f1) & 0xef;
      }
      FUN_80101c10(2);
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x52,1,0,0,0,0x2d,0xff);
      *(byte *)(param_2 + 0x3f6) = *(byte *)(param_2 + 0x3f6) & 0xbf | 0x40;
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0x2a);
      *(code **)(param_2 + 0x304) = FUN_8029ac08;
      FUN_802abaec((uint)param_1,param_2,(int)*(short *)(param_2 + 0x80c));
    }
  }
LAB_802aff1c:
  if (bVar3) {
    FUN_8000bb38(0,0x10a);
  }
LAB_802aff34:
  *(undefined2 *)(param_2 + 0x80c) = 0xffff;
  return;
}

