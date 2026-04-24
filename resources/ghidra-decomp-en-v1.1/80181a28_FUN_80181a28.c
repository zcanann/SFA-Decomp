// Function: FUN_80181a28
// Entry: 80181a28
// Size: 552 bytes

void FUN_80181a28(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  bool bVar6;
  int *piVar4;
  ushort uVar5;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  float *pfVar10;
  undefined4 in_r10;
  double dVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  int local_48;
  uint uStack_44;
  int iStack_40;
  int local_3c;
  undefined auStack_38 [12];
  float local_2c;
  undefined4 uStack_28;
  float local_24 [9];
  
  uVar13 = FUN_80286840();
  puVar2 = (ushort *)((ulonglong)uVar13 >> 0x20);
  pfVar10 = local_24;
  iVar3 = FUN_80036868((int)puVar2,&local_3c,&iStack_40,&uStack_44,&local_2c,&uStack_28,pfVar10);
  if (iVar3 != 0) {
    if (iVar3 == 0x10) {
      FUN_8002b128(puVar2,300);
    }
    else {
      local_2c = local_2c + FLOAT_803dda58;
      local_24[0] = local_24[0] + FLOAT_803dda5c;
      if (*(char *)(param_11 + 0x20) != '\0') {
        if (iVar3 != 5) {
          FUN_8009a468(puVar2,auStack_38,4,(int *)0x0);
          bVar6 = FUN_8000b5f0(0,0x37e);
          if (!bVar6) {
            FUN_8000bb38((uint)puVar2,0x37e);
          }
          goto LAB_80181c38;
        }
        piVar4 = FUN_80037048(0x10,&local_48);
        for (iVar3 = 0; iVar3 < local_48; iVar3 = iVar3 + 1) {
          uVar5 = FUN_80036074(*piVar4);
          if (uVar5 != 0) {
            param_2 = (double)*(float *)(*piVar4 + 0x10);
            if ((((double)*(float *)(puVar2 + 8) < param_2) &&
                (param_2 < (double)(float)((double)*(float *)(puVar2 + 8) + (double)FLOAT_803dca10))
                ) && (dVar11 = (double)FUN_80021754((float *)(*piVar4 + 0x18),
                                                    (float *)(puVar2 + 0xc)),
                     dVar11 < (double)FLOAT_803dca0c)) {
              FUN_80036548(*piVar4,local_3c,'\x05',1,0);
            }
          }
          piVar4 = piVar4 + 1;
        }
      }
      FUN_8009a468(puVar2,auStack_38,1,(int *)0x0);
      uVar7 = 0;
      uVar8 = 0;
      uVar9 = 1;
      uVar12 = FUN_8002ad08(puVar2,0xf,200,0,0,1);
      bVar6 = FUN_8000b5f0(0,*(short *)(param_11 + 0x10));
      if (!bVar6) {
        uVar12 = FUN_8000bb38((uint)puVar2,*(ushort *)(param_11 + 0x10));
      }
      *(undefined2 *)(param_11 + 10) = 0x32;
      *(undefined *)(param_11 + 9) = 0;
      FUN_80181c50(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,(int)uVar13
                   ,param_11,uVar7,uVar8,uVar9,pfVar10,in_r10);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      fVar1 = FLOAT_803e45d0;
      *(float *)(puVar2 + 0x12) = FLOAT_803e45d0;
      *(float *)(puVar2 + 0x16) = fVar1;
      FUN_80035ea4((int)puVar2);
      if (DAT_803dca08 != 0) {
        FUN_80035ff8((int)puVar2);
      }
    }
  }
LAB_80181c38:
  FUN_8028688c();
  return;
}

