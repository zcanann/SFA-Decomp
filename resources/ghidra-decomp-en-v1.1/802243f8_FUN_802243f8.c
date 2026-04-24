// Function: FUN_802243f8
// Entry: 802243f8
// Size: 336 bytes

void FUN_802243f8(ushort *param_1)

{
  int iVar1;
  uint *puVar2;
  double dVar3;
  float local_78;
  float local_74;
  float local_70;
  ushort local_6c;
  ushort local_6a;
  ushort local_68;
  float local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  float afStack_54 [19];
  
  puVar2 = *(uint **)(param_1 + 0x5c);
  iVar1 = FUN_8002bac4();
  dVar3 = (double)FUN_80021754((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
  puVar2[0x2ae] = (uint)(float)dVar3;
  *puVar2 = *puVar2 | 0x2000000;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_1,puVar2,&DAT_803adee8,
             &DAT_803aded8);
  if ((*(byte *)(puVar2 + 0x2b0) & 1) == 0) {
    *(byte *)((int)puVar2 + 0x96d) = *(byte *)((int)puVar2 + 0x96d) | 1;
  }
  else {
    *(byte *)((int)puVar2 + 0x96d) = *(byte *)((int)puVar2 + 0x96d) & 0xfe;
  }
  FUN_80115330();
  FUN_8003b408((int)param_1,(int)(puVar2 + 0x260));
  local_60 = *(undefined4 *)(param_1 + 6);
  local_5c = *(undefined4 *)(param_1 + 8);
  local_58 = *(undefined4 *)(param_1 + 10);
  local_6c = *param_1;
  local_6a = param_1[1];
  local_68 = param_1[2];
  local_64 = FLOAT_803e79b0;
  FUN_80021fac(afStack_54,&local_6c);
  dVar3 = (double)FLOAT_803e7990;
  FUN_80022790(dVar3,dVar3,dVar3,afStack_54,&local_78,&local_74,&local_70);
  FUN_80062bcc();
  return;
}

