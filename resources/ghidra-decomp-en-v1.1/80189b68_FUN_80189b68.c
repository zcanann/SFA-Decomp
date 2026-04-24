// Function: FUN_80189b68
// Entry: 80189b68
// Size: 584 bytes

/* WARNING: Removing unreachable block (ram,0x80189d90) */
/* WARNING: Removing unreachable block (ram,0x80189c24) */
/* WARNING: Removing unreachable block (ram,0x80189b78) */

void FUN_80189b68(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps31_1;
  undefined8 uVar9;
  float local_48 [16];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar9 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar5 = *(int *)(iVar3 + 0x4c);
  if (((char)*(byte *)(iVar4 + 0x1d) < '\0') &&
     (((*(byte *)(iVar4 + 0x1d) >> 6 & 1) == 0 || (*(char *)(iVar4 + 0x1c) != '\0')))) {
    if (*(char *)(iVar4 + 0x1c) == '\0') {
      if (*(char *)(iVar5 + 0x1e) == '\x02') {
        uVar1 = FUN_80022264(0xffffff38,200);
        *(short *)(iVar3 + 2) = (short)uVar1;
        uVar1 = FUN_80022264(0xffffff38,200);
        *(short *)(iVar3 + 4) = (short)uVar1;
      }
      FUN_80037c38(iVar3,8,0xb4,0xf0,0xff,0x6f,(float *)(iVar4 + 0x20));
    }
    else {
      *(undefined2 *)(iVar3 + 2) = 0;
      *(undefined2 *)(iVar3 + 4) = 0;
      dVar7 = (double)*(float *)(iVar3 + 0x98);
      if (((double)FLOAT_803e4854 <= dVar7) && ((*(byte *)(iVar4 + 0x1d) >> 4 & 1) == 0)) {
        if (0 < *(short *)(iVar5 + 0x24)) {
          dVar7 = (double)FUN_800201ac((int)*(short *)(iVar5 + 0x24),1);
        }
        if (*(char *)(iVar5 + 0x1e) == '\x01') {
          local_48[0] = FLOAT_803e4858;
          iVar3 = FUN_80036f50(0x41,iVar3,local_48);
          if (iVar3 != 0) {
            iVar5 = *(int *)(iVar3 + 0xb8);
            uVar1 = (uint)*(short *)(*(int *)(iVar3 + 0x4c) + 0x22);
            if (0 < (int)uVar1) {
              FUN_800201ac(uVar1,1);
            }
            *(byte *)(iVar5 + 0x1d) = *(byte *)(iVar5 + 0x1d) & 0x7f | 0x80;
          }
        }
        else if ((*(char *)(iVar5 + 0x1e) == '\0') && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0))
        {
          dVar8 = (double)FLOAT_803e4850;
          for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar5 + 0x1f); iVar6 = iVar6 + 1) {
            puVar2 = FUN_8002becc(0x24,0x259);
            *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar3 + 0xc);
            *(float *)(puVar2 + 6) = (float)(dVar8 + (double)*(float *)(iVar3 + 0x10));
            *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar3 + 0x14);
            *(undefined *)(puVar2 + 2) = 1;
            dVar7 = (double)FUN_8002e088(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,
                                         param_8,puVar2,5,*(undefined *)(iVar3 + 0xac),0xffffffff,
                                         *(uint **)(iVar3 + 0x30),in_r8,in_r9,in_r10);
          }
        }
        *(undefined *)(iVar4 + 0x1c) = 0;
        *(byte *)(iVar4 + 0x1d) = *(byte *)(iVar4 + 0x1d) & 0xef | 0x10;
      }
      *(byte *)(iVar4 + 0x1d) = *(byte *)(iVar4 + 0x1d) & 0xbf | 0x40;
      *(float *)(iVar4 + 8) = FLOAT_803e485c;
    }
    FUN_8002fb40((double)*(float *)(iVar4 + 8),(double)FLOAT_803dc074);
  }
  FUN_8028688c();
  return;
}

