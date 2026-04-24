// Function: FUN_80203670
// Entry: 80203670
// Size: 1080 bytes

void FUN_80203670(void)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  int local_48;
  undefined4 local_44;
  undefined auStack64 [4];
  float local_3c;
  float local_38;
  float local_34;
  
  iVar2 = FUN_802860cc();
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar7 = *(int *)(iVar2 + 0x4c);
  iVar6 = *(int *)(iVar8 + 0x40c);
  *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
  if ((*(byte *)(iVar6 + 0x44) >> 4 & 1) != 0) {
    sVar1 = *(short *)(iVar7 + 0x24);
    uVar3 = FUN_800139e8(0x14,0xc);
    *(undefined4 *)(iVar6 + 0x24) = uVar3;
    iVar4 = (int)*(short *)(&DAT_80329518 + sVar1 * 8);
    iVar5 = iVar4 * 0xc;
    for (; iVar4 != 0; iVar4 = iVar4 + -1) {
      iVar5 = iVar5 + -0xc;
      FUN_80013958(*(undefined4 *)(iVar6 + 0x24),(&PTR_DAT_80329514)[sVar1 * 2] + iVar5);
    }
    *(undefined *)(iVar6 + 0x34) = 1;
    *(byte *)(iVar6 + 0x44) = *(byte *)(iVar6 + 0x44) & 0xef;
  }
  iVar6 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x3f6));
  if (iVar6 != 0) {
    if (*(int *)(iVar2 + 0xf4) == 0) {
      if (*(int *)(iVar2 + 0xf8) == 0) {
        *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar7 + 8);
        *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
        *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
        (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar7 + 0x2e),iVar2,0xffffffff);
        *(undefined4 *)(iVar2 + 0xf8) = 1;
      }
      else {
        iVar6 = (**(code **)(*DAT_803dcab8 + 0x30))(iVar2,iVar8,0);
        if (iVar6 == 0) {
          *(undefined2 *)(iVar8 + 0x402) = 0;
        }
        else {
          iVar6 = *(int *)(iVar8 + 0x2d0);
          if (iVar6 != 0) {
            local_3c = *(float *)(iVar6 + 0x18) - *(float *)(iVar2 + 0x18);
            local_38 = *(float *)(iVar6 + 0x1c) - *(float *)(iVar2 + 0x1c);
            local_34 = *(float *)(iVar6 + 0x20) - *(float *)(iVar2 + 0x20);
            dVar9 = (double)FUN_802931a0((double)(local_34 * local_34 +
                                                 local_3c * local_3c + local_38 * local_38));
            *(float *)(iVar8 + 0x2c0) = (float)dVar9;
          }
          local_48 = 0;
          local_44 = 0;
          iVar6 = *(int *)(*(int *)(iVar2 + 0xb8) + 0x40c);
          while (iVar7 = FUN_800374ec(iVar2,&local_48,auStack64,&local_44), iVar7 != 0) {
            if ((local_48 == 0x11) && (*(short *)(iVar6 + 0x1c) != -1)) {
              FUN_800378c4(*(undefined4 *)(iVar6 + 0x18),0x11,iVar2,0x14);
              *(undefined4 *)(iVar6 + 0x18) = 0;
              *(undefined2 *)(iVar6 + 0x1c) = 0xffff;
              FUN_80030334((double)FLOAT_803e62a8,iVar2,0xf,0);
            }
          }
          iVar6 = (**(code **)(*DAT_803dcab8 + 0x50))
                            (iVar2,iVar8,iVar8 + 0x35c,(int)*(short *)(iVar8 + 0x3f4),&DAT_80329664,
                             &DAT_803296dc,1,&DAT_803ad0c0);
          if (iVar6 != 0) {
            DAT_803ad0cc = *(undefined4 *)(iVar2 + 0xc);
            DAT_803ad0d0 = *(undefined4 *)(iVar2 + 0x10);
            DAT_803ad0d4 = *(undefined4 *)(iVar2 + 0x14);
            FUN_8009a1dc((double)FLOAT_803e638c,iVar2,&DAT_803ad0c0,1,0);
          }
          if (*(short *)(iVar8 + 0x402) == 0) {
            FUN_80203144(iVar2,iVar8,iVar8);
          }
          else {
            iVar6 = *(int *)(iVar8 + 0x40c);
            FUN_80203000(iVar2,iVar8);
            (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e6388,iVar2,iVar8,0xffffffff);
            if ((*(byte *)(iVar6 + 0x15) & 4) == 0) {
              (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,iVar2,iVar8,4);
            }
            *(undefined4 *)(iVar8 + 0x3e0) = *(undefined4 *)(iVar2 + 0xc0);
            *(undefined4 *)(iVar2 + 0xc0) = 0;
            (**(code **)(*DAT_803dca8c + 8))
                      ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar2,iVar8,&DAT_803ad0f4,
                       &DAT_803ad0d8);
            *(undefined4 *)(iVar2 + 0xc0) = *(undefined4 *)(iVar8 + 0x3e0);
          }
        }
      }
    }
    else if (((*(byte *)(iVar8 + 0x404) & 4) == 0) &&
            (iVar6 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar7 + 0x14)), iVar6 != 0)
            ) {
      (**(code **)(*DAT_803dcab8 + 0x58))
                ((double)FLOAT_803e62fc,iVar2,iVar7,iVar8,0x10,7,0x10a,0x26);
      FUN_80037200(iVar2,3);
      *(undefined2 *)(iVar8 + 0x402) = 0;
      FUN_80030334((double)FLOAT_803e62a8,iVar2,8,0x10);
      *(undefined *)(iVar8 + 0x346) = 0;
      *(undefined *)(iVar2 + 0x36) = 0xff;
      *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
    }
  }
  FUN_80286118();
  return;
}

