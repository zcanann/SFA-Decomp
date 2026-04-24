// Function: FUN_80189610
// Entry: 80189610
// Size: 584 bytes

/* WARNING: Removing unreachable block (ram,0x801896cc) */
/* WARNING: Removing unreachable block (ram,0x80189838) */

void FUN_80189610(void)

{
  int iVar1;
  char cVar4;
  int iVar2;
  undefined2 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  float local_48;
  undefined auStack68 [60];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar6 = *(int *)(iVar1 + 0x4c);
  if (((char)*(byte *)(iVar5 + 0x1d) < '\0') &&
     (((*(byte *)(iVar5 + 0x1d) >> 6 & 1) == 0 || (*(char *)(iVar5 + 0x1c) != '\0')))) {
    if (*(char *)(iVar5 + 0x1c) == '\0') {
      if (*(char *)(iVar6 + 0x1e) == '\x02') {
        uVar3 = FUN_800221a0(0xffffff38,200);
        *(undefined2 *)(iVar1 + 2) = uVar3;
        uVar3 = FUN_800221a0(0xffffff38,200);
        *(undefined2 *)(iVar1 + 4) = uVar3;
      }
      FUN_80037b40(iVar1,8,0xb4,0xf0,0xff,0x6f,iVar5 + 0x20);
    }
    else {
      *(undefined2 *)(iVar1 + 2) = 0;
      *(undefined2 *)(iVar1 + 4) = 0;
      if ((FLOAT_803e3bbc <= *(float *)(iVar1 + 0x98)) && ((*(byte *)(iVar5 + 0x1d) >> 4 & 1) == 0))
      {
        if (0 < *(short *)(iVar6 + 0x24)) {
          FUN_800200e8((int)*(short *)(iVar6 + 0x24),1);
        }
        if (*(char *)(iVar6 + 0x1e) == '\x01') {
          local_48 = FLOAT_803e3bc0;
          iVar6 = FUN_80036e58(0x41,iVar1,&local_48);
          if (iVar6 != 0) {
            iVar7 = *(int *)(iVar6 + 0xb8);
            iVar6 = (int)*(short *)(*(int *)(iVar6 + 0x4c) + 0x22);
            if (0 < iVar6) {
              FUN_800200e8(iVar6,1);
            }
            *(byte *)(iVar7 + 0x1d) = *(byte *)(iVar7 + 0x1d) & 0x7f | 0x80;
          }
        }
        else if ((*(char *)(iVar6 + 0x1e) == '\0') && (cVar4 = FUN_8002e04c(), cVar4 != '\0')) {
          dVar9 = (double)FLOAT_803e3bb8;
          for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(iVar6 + 0x1f); iVar7 = iVar7 + 1) {
            iVar2 = FUN_8002bdf4(0x24,0x259);
            *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(iVar1 + 0xc);
            *(float *)(iVar2 + 0xc) = (float)(dVar9 + (double)*(float *)(iVar1 + 0x10));
            *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar1 + 0x14);
            *(undefined *)(iVar2 + 4) = 1;
            FUN_8002df90(iVar2,5,(int)*(char *)(iVar1 + 0xac),0xffffffff,
                         *(undefined4 *)(iVar1 + 0x30));
          }
        }
        *(undefined *)(iVar5 + 0x1c) = 0;
        *(byte *)(iVar5 + 0x1d) = *(byte *)(iVar5 + 0x1d) & 0xef | 0x10;
      }
      *(byte *)(iVar5 + 0x1d) = *(byte *)(iVar5 + 0x1d) & 0xbf | 0x40;
      *(float *)(iVar5 + 8) = FLOAT_803e3bc4;
    }
    FUN_8002fa48((double)*(float *)(iVar5 + 8),(double)FLOAT_803db414,iVar1,auStack68);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286128();
  return;
}

