// Function: FUN_80157cdc
// Entry: 80157cdc
// Size: 480 bytes

void FUN_80157cdc(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  byte bVar5;
  undefined *puVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  puVar6 = (&PTR_DAT_8031fb04)[(uint)*(byte *)(iVar4 + 0x33b) * 8];
  FLOAT_803dda70 = FLOAT_803dda70 - FLOAT_803db414;
  for (bVar5 = 0; bVar5 < 0xd; bVar5 = bVar5 + 1) {
    uVar1 = (uint)bVar5;
    if (((uint)*(ushort *)(iVar4 + 0x2f8) & 1 << uVar1) != 0) {
      if (*(uint *)(puVar6 + uVar1 * 0xc + 4) != 0) {
        FUN_8000bb18(iVar2,*(uint *)(puVar6 + uVar1 * 0xc + 4) & 0xffff);
      }
      if ((byte)puVar6[uVar1 * 0xc + 9] != 0) {
        FUN_8000e718((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                     (double)*(float *)(iVar2 + 0x14),(double)FLOAT_803e2ba0,
                     (double)(float)((double)CONCAT44(0x43300000,(uint)(byte)puVar6[uVar1 * 0xc + 9]
                                                     ) - DOUBLE_803e2b90));
      }
      if ((puVar6[uVar1 * 0xc + 10] != '\0') &&
         (iVar3 = FUN_8002b9ec(), (*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
        dVar7 = (double)FUN_80021704(iVar2 + 0x18,iVar3 + 0x18);
        if (dVar7 <= (double)FLOAT_803e2b80) {
          FUN_80014aa0((double)((FLOAT_803e2ba4 - (float)(dVar7 / (double)FLOAT_803e2b80)) *
                               (float)((double)CONCAT44(0x43300000,
                                                        (uint)(byte)puVar6[uVar1 * 0xc + 10]) -
                                      DOUBLE_803e2b90)));
        }
      }
      if (puVar6[uVar1 * 0xc + 0xb] != 0) {
        if ((puVar6[uVar1 * 0xc + 0xb] & 1) != 0) {
          *(byte *)(iVar4 + 0x33d) = *(byte *)(iVar4 + 0x33d) ^ 0x40;
          if ((*(byte *)(iVar4 + 0x33d) & 0x40) == 0) {
            if (*(int *)(iVar2 + 200) != 0) {
              FUN_8021fab4();
            }
          }
          else if (*(int *)(iVar2 + 200) == 0) {
            FUN_80157a58(iVar2,iVar4);
          }
          else {
            FUN_8021fad0();
          }
        }
        if ((puVar6[uVar1 * 0xc + 0xb] & 2) != 0) {
          FUN_80157b58(iVar2,iVar4);
        }
      }
    }
  }
  FUN_80286128();
  return;
}

