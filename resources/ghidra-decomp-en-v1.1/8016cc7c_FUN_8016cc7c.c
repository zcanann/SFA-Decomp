// Function: FUN_8016cc7c
// Entry: 8016cc7c
// Size: 468 bytes

void FUN_8016cc7c(void)

{
  ushort *puVar1;
  ushort *puVar2;
  int iVar3;
  float afStack_288 [12];
  float afStack_258 [12];
  float afStack_228 [12];
  float afStack_1f8 [12];
  float afStack_1c8 [12];
  float afStack_198 [3];
  float local_18c;
  float local_17c;
  float local_16c;
  float afStack_168 [12];
  float afStack_138 [12];
  float afStack_108 [12];
  float afStack_d8 [12];
  float afStack_a8 [12];
  float afStack_78 [12];
  float afStack_48 [18];
  
  puVar1 = (ushort *)FUN_80286840();
  FUN_8016c958((int)puVar1);
  if ((*(byte *)(*(int *)(puVar1 + 0x5c) + 0x7f) & 4) == 0) {
    FUN_8003b9ec((int)puVar1);
  }
  else {
    FUN_8002b554(puVar1,afStack_48,'\0');
    iVar3 = *(int *)(puVar1 + 0x26);
    FUN_80247a48(-(double)(*(float *)(iVar3 + 8) - FLOAT_803dda58),-(double)*(float *)(iVar3 + 0xc),
                 -(double)(*(float *)(iVar3 + 0x10) - FLOAT_803dda5c),afStack_78);
    FUN_80247618(afStack_78,afStack_48,afStack_a8);
    puVar2 = (ushort *)(**(code **)(*DAT_803dd6d0 + 0xc))();
    puVar2[1] = puVar2[1] + 0x8000;
    *(float *)(puVar2 + 4) = FLOAT_803e3f08;
    FUN_8002b554(puVar2,afStack_198,'\0');
    puVar2[1] = puVar2[1] + 0x8000;
    *(float *)(puVar2 + 4) = FLOAT_803e3ef4;
    FUN_80247a48(-(double)local_18c,-(double)local_17c,-(double)local_16c,afStack_d8);
    FUN_8024782c((double)FLOAT_803e3f14,afStack_108,0x79);
    FUN_8024782c((double)FLOAT_803e3f14,afStack_138,0x7a);
    FUN_80247a48((double)local_18c,(double)local_17c,(double)local_16c,afStack_168);
    FUN_80247618(afStack_d8,afStack_198,afStack_1c8);
    FUN_80247618(afStack_108,afStack_1c8,afStack_1f8);
    FUN_80247618(afStack_138,afStack_1f8,afStack_228);
    FUN_80247618(afStack_168,afStack_228,afStack_258);
    FUN_80247618(afStack_258,afStack_a8,afStack_288);
    FUN_800413cc(afStack_288);
    FUN_80041bbc((int)puVar1);
  }
  FUN_8028688c();
  return;
}

