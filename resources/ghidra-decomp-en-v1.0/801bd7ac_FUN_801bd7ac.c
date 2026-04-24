// Function: FUN_801bd7ac
// Entry: 801bd7ac
// Size: 804 bytes

void FUN_801bd7ac(int param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  local_28 = DAT_802c2338;
  local_24 = DAT_802c233c;
  local_20 = DAT_802c2340;
  local_1c = DAT_802c2344;
  FUN_8005cef0(0);
  *(undefined *)(param_1 + 0xe4) = 2;
  uVar4 = 6;
  if (param_3 != 0) {
    uVar4 = 7;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))
            ((double)FLOAT_803e4c28,param_1,param_2,iVar5,0xc,6,0x102,uVar4);
  *(code **)(param_1 + 0xbc) = FUN_801bcb34;
  *(undefined2 *)(iVar5 + 0x402) = 0;
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar5,0);
  *(undefined2 *)(iVar5 + 0x270) = 0;
  *(undefined *)(iVar5 + 0x354) = 3;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x88;
  iVar2 = FUN_8001ffb4(0x210);
  if (iVar2 != 0) {
    *(undefined2 *)(iVar5 + 0x402) = 4;
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  iVar2 = FUN_8001ffb4(0x20e);
  if (iVar2 != 0) {
    *(undefined2 *)(iVar5 + 0x402) = 3;
  }
  fVar1 = FLOAT_803e4bd8;
  puVar6 = *(undefined4 **)(iVar5 + 0x40c);
  puVar6[0x2a] = FLOAT_803e4bd8;
  puVar6[0x29] = fVar1;
  *(undefined2 *)(param_1 + 0xa2) = 0xffff;
  *puVar6 = 0;
  DAT_803ddb84 = 0;
  DAT_803ddb80 = 0;
  FUN_800200e8(0x4e4,1);
  FUN_80114f64(param_1,&DAT_803ac9dc,0xffffd8e4,0x1c71,6);
  FUN_80113f9c(&DAT_803ac9dc,&local_28,&local_28,6);
  DAT_803acfed = DAT_803acfed & 0xfe | 8;
  *(byte *)((int)puVar6 + 0xb6) = *(byte *)((int)puVar6 + 0xb6) & 0x7f | 0x80;
  DAT_803ddb88 = FUN_80013ec8(0x5a,1);
  iVar5 = FUN_8001ffb4(0x1df);
  if (iVar5 == 0) {
    *(undefined *)(puVar6 + 0x2d) = 2;
    puVar6[0x2b] = FLOAT_803e4c78;
    (**(code **)(*DAT_803dcaac + 0x50))(0x1c,5,1);
  }
  else {
    (**(code **)(*DAT_803dcaac + 0x50))(0x1c,5,0);
  }
  puVar6[0x2c] = 0;
  cVar3 = (**(code **)(*DAT_803dcaac + 0x40))(7);
  if (cVar3 == '\x02') {
    (**(code **)(*DAT_803dcaac + 0x44))(7,3);
  }
  FUN_800200e8(0xefd,1);
  FUN_8004350c(0,0,1);
  uVar4 = FUN_800481b0(0x1c);
  FUN_80043560(uVar4,1);
  uVar4 = FUN_800481b0(0x1b);
  FUN_80043560(uVar4,0);
  FUN_800200e8(0xcbb,0);
  FUN_8000a518(0x36,1);
  FUN_800200e8(0xda5,0);
  FUN_8000a518(0xd7,0);
  FUN_8000a518(0xe0,0);
  return;
}

