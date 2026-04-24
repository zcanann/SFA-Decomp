// Function: FUN_801b5aa0
// Entry: 801b5aa0
// Size: 520 bytes

void FUN_801b5aa0(short *param_1)

{
  short sVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  bool bVar5;
  float *pfVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0x26);
  pfVar6 = *(float **)(param_1 + 0x5c);
  if (*(char *)(param_1 + 0x1b) != '\0') {
    if ((*(char *)((int)pfVar6 + 9) < '\x01') &&
       (*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe, *(char *)(pfVar6 + 2) == '\x01')
       ) {
      *pfVar6 = pfVar6[1] * FLOAT_803db414 + *pfVar6;
      if (*pfVar6 <= FLOAT_803e49ec) {
        if (*pfVar6 < FLOAT_803e49f4) {
          *pfVar6 = FLOAT_803e49f4;
          pfVar6[1] = FLOAT_803e49f8;
        }
      }
      else {
        *pfVar6 = FLOAT_803e49ec;
        pfVar6[1] = FLOAT_803e49f0;
      }
    }
    if (param_1[0x23] != 0x334) {
      bVar5 = false;
      iVar4 = 0;
      iVar2 = (int)*(char *)(*(int *)(param_1 + 0x2c) + 0x10f);
      if (0 < iVar2) {
        do {
          sVar1 = *(short *)(*(int *)(*(int *)(param_1 + 0x2c) + iVar4 + 0x100) + 0x46);
          if ((sVar1 == 399) || (sVar1 == 0x1d6)) {
            bVar5 = true;
            break;
          }
          iVar4 = iVar4 + 4;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
      if ((bVar5) &&
         (cVar3 = *(char *)((int)pfVar6 + 9) + -1, *(char *)((int)pfVar6 + 9) = cVar3,
         cVar3 < '\x01')) {
        FUN_800200e8((int)*(short *)(iVar7 + 0x1e),1);
        *(undefined *)(pfVar6 + 2) = 1;
        iVar2 = FUN_8001ffb4(0x46d);
        if ((*(short *)(iVar7 + 0x1a) == iVar2) && (cVar3 = FUN_8002e04c(), cVar3 != '\0')) {
          iVar2 = FUN_8002bdf4(0x30,0x246);
          *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(iVar7 + 8);
          *(float *)(iVar2 + 0xc) = FLOAT_803e49fc + *(float *)(iVar7 + 0xc);
          *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar7 + 0x10);
          *(undefined *)(iVar2 + 4) = *(undefined *)(iVar7 + 4);
          *(undefined *)(iVar2 + 5) = *(undefined *)(iVar7 + 5);
          *(undefined *)(iVar2 + 6) = *(undefined *)(iVar7 + 6);
          *(undefined *)(iVar2 + 7) = *(undefined *)(iVar7 + 7);
          *(undefined2 *)(iVar2 + 0x1c) = 0x17f;
          *(undefined2 *)(iVar2 + 0x24) = 0xffff;
          *(undefined2 *)(iVar2 + 0x2c) = 0xffff;
          *(undefined *)(iVar2 + 0x1a) = 5;
          *(char *)(iVar2 + 0x1b) = (char)((uint)(int)*param_1 >> 8);
          FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0x56),0xffffffff,0);
        }
      }
    }
  }
  return;
}

