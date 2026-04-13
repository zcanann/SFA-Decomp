// Function: FUN_801b6054
// Entry: 801b6054
// Size: 520 bytes

void FUN_801b6054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  char cVar4;
  uint uVar5;
  undefined2 *puVar6;
  int iVar7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar8;
  int iVar9;
  double dVar10;
  
  iVar9 = *(int *)(param_9 + 0x26);
  pfVar8 = *(float **)(param_9 + 0x5c);
  if (*(char *)(param_9 + 0x1b) != '\0') {
    if ((*(char *)((int)pfVar8 + 9) < '\x01') &&
       (*(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe, *(char *)(pfVar8 + 2) == '\x01')
       ) {
      param_2 = (double)pfVar8[1];
      *pfVar8 = (float)(param_2 * (double)FLOAT_803dc074 + (double)*pfVar8);
      if (*pfVar8 <= FLOAT_803e5684) {
        if (*pfVar8 < FLOAT_803e568c) {
          *pfVar8 = FLOAT_803e568c;
          pfVar8[1] = FLOAT_803e5690;
        }
      }
      else {
        *pfVar8 = FLOAT_803e5684;
        pfVar8[1] = FLOAT_803e5688;
      }
    }
    if (param_9[0x23] != 0x334) {
      bVar2 = false;
      iVar7 = 0;
      iVar3 = (int)*(char *)(*(int *)(param_9 + 0x2c) + 0x10f);
      if (0 < iVar3) {
        do {
          sVar1 = *(short *)(*(int *)(*(int *)(param_9 + 0x2c) + iVar7 + 0x100) + 0x46);
          if ((sVar1 == 399) || (sVar1 == 0x1d6)) {
            bVar2 = true;
            break;
          }
          iVar7 = iVar7 + 4;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      if ((bVar2) &&
         (cVar4 = *(char *)((int)pfVar8 + 9) + -1, *(char *)((int)pfVar8 + 9) = cVar4,
         cVar4 < '\x01')) {
        FUN_800201ac((int)*(short *)(iVar9 + 0x1e),1);
        *(undefined *)(pfVar8 + 2) = 1;
        uVar5 = FUN_80020078(0x46d);
        if (((int)*(short *)(iVar9 + 0x1a) == uVar5) &&
           (uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
          puVar6 = FUN_8002becc(0x30,0x246);
          *(undefined4 *)(puVar6 + 4) = *(undefined4 *)(iVar9 + 8);
          dVar10 = (double)FLOAT_803e5694;
          *(float *)(puVar6 + 6) = (float)(dVar10 + (double)*(float *)(iVar9 + 0xc));
          *(undefined4 *)(puVar6 + 8) = *(undefined4 *)(iVar9 + 0x10);
          *(undefined *)(puVar6 + 2) = *(undefined *)(iVar9 + 4);
          *(undefined *)((int)puVar6 + 5) = *(undefined *)(iVar9 + 5);
          *(undefined *)(puVar6 + 3) = *(undefined *)(iVar9 + 6);
          *(undefined *)((int)puVar6 + 7) = *(undefined *)(iVar9 + 7);
          puVar6[0xe] = 0x17f;
          puVar6[0x12] = 0xffff;
          puVar6[0x16] = 0xffff;
          *(undefined *)(puVar6 + 0xd) = 5;
          *(char *)((int)puVar6 + 0x1b) = (char)((ushort)*param_9 >> 8);
          FUN_8002e088(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar6,5,
                       *(undefined *)(param_9 + 0x56),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        }
      }
    }
  }
  return;
}

