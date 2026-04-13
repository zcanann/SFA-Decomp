// Function: FUN_80158188
// Entry: 80158188
// Size: 480 bytes

void FUN_80158188(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  byte bVar5;
  undefined *puVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286840();
  uVar2 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  puVar6 = (&PTR_DAT_80320754)[(uint)*(byte *)(iVar4 + 0x33b) * 8];
  dVar7 = (double)FLOAT_803de6f0;
  FLOAT_803de6f0 = (float)(dVar7 - (double)FLOAT_803dc074);
  for (bVar5 = 0; bVar5 < 0xd; bVar5 = bVar5 + 1) {
    uVar1 = (uint)bVar5;
    if (((uint)*(ushort *)(iVar4 + 0x2f8) & 1 << uVar1) != 0) {
      if (*(int *)(puVar6 + uVar1 * 0xc + 4) != 0) {
        dVar7 = (double)FUN_8000bb38(uVar2,(ushort)*(int *)(puVar6 + uVar1 * 0xc + 4));
      }
      if ((byte)puVar6[uVar1 * 0xc + 9] != 0) {
        param_2 = (double)*(float *)(uVar2 + 0x10);
        param_3 = (double)*(float *)(uVar2 + 0x14);
        param_4 = (double)FLOAT_803e3838;
        param_5 = (double)(float)((double)CONCAT44(0x43300000,(uint)(byte)puVar6[uVar1 * 0xc + 9]) -
                                 DOUBLE_803e3828);
        dVar7 = (double)FUN_8000e738((double)*(float *)(uVar2 + 0xc),param_2,param_3,param_4,param_5
                                    );
      }
      if ((puVar6[uVar1 * 0xc + 10] != '\0') &&
         (iVar3 = FUN_8002bac4(), (*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
        dVar7 = (double)FUN_800217c8((float *)(uVar2 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar7 <= (double)FLOAT_803e3818) {
          param_2 = (double)(FLOAT_803e383c - (float)(dVar7 / (double)FLOAT_803e3818));
          dVar7 = (double)FUN_80014acc((double)(float)(param_2 *
                                                      (double)(float)((double)CONCAT44(0x43300000,
                                                                                       (uint)(byte)
                                                  puVar6[uVar1 * 0xc + 10]) - DOUBLE_803e3828)));
        }
      }
      if (puVar6[uVar1 * 0xc + 0xb] != 0) {
        if ((puVar6[uVar1 * 0xc + 0xb] & 1) != 0) {
          *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) ^ 0x40;
          if ((*(byte *)(iVar4 + 0x33d) & 0x40) == 0) {
            if (*(int *)(uVar2 + 200) != 0) {
              FUN_80220104(*(int *)(uVar2 + 200));
            }
          }
          else if (*(int *)(uVar2 + 200) == 0) {
            dVar7 = (double)FUN_80157f04(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,
                                         param_8,uVar2);
          }
          else {
            FUN_80220120(*(int *)(uVar2 + 200));
          }
        }
        if ((puVar6[uVar1 * 0xc + 0xb] & 2) != 0) {
          dVar7 = (double)FUN_80158004(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                       ,uVar2,iVar4);
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

