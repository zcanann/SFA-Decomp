// Function: FUN_8005c174
// Entry: 8005c174
// Size: 1500 bytes

void FUN_8005c174(void)

{
  undefined4 uVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 local_288;
  float local_284;
  float local_280;
  undefined4 local_27c;
  undefined auStack632 [616];
  
  DAT_803dce34 = FUN_80094390(&local_280,&local_284);
  if (DAT_803dce34 != 0) {
    DAT_80382008 = FLOAT_803dec10;
    DAT_8038200c = FLOAT_803debcc;
    DAT_80382010 = FLOAT_803debcc;
    DAT_80382014 = FLOAT_803dec10 * FLOAT_803dcdd8 + local_280;
    DAT_80382018 = FLOAT_803debcc;
    DAT_8038201c = FLOAT_803debcc;
    DAT_80382020 = FLOAT_803dec10;
    DAT_80382024 = FLOAT_803dec10 * FLOAT_803dcddc + local_284;
    DAT_80382028 = FLOAT_803debcc;
    DAT_8038202c = FLOAT_803debcc;
    DAT_80382030 = FLOAT_803debcc;
    DAT_80382034 = FLOAT_803debdc;
    uVar1 = FUN_8000f558();
    FUN_80246eb4(&DAT_80382008,uVar1,&DAT_80382008);
  }
  FUN_8005a45c(&DAT_80382224);
  FUN_80062894();
  FUN_80062808();
  DAT_803dceae = 1;
  DAT_803dceac = 0;
  DAT_803dce06 = 0;
  FUN_8006c7a8();
  DAT_803dce30 = 0;
  FUN_8005b654(auStack632);
  FUN_80052efc();
  FUN_80129db4();
  FUN_802584c0();
  FUN_8000f0fc(0,0);
  FUN_8000f564();
  FUN_8000fb00();
  iVar2 = 0;
  if (((DAT_803dcde8 & 0x40) != 0) && ((DAT_803dcde8 & 0x80000) == 0)) {
    iVar2 = 1;
  }
  if ((DAT_803dcde8 & 0x40000) == 0) {
    (**(code **)(*DAT_803dca58 + 0x10))(0,0,0,0,iVar2);
    (**(code **)(*DAT_803dca64 + 0x10))(0,0,0,0);
    FUN_80093ae0();
  }
  else {
    (**(code **)(*DAT_803dca58 + 0x38))(0,0);
    if (iVar2 != 0) {
      FUN_80093ae0();
    }
    (**(code **)(*DAT_803dca58 + 0x10))(0,0,0,0,iVar2);
    if ((DAT_803dcde8 & 0x10) != 0) {
      (**(code **)(*DAT_803dca64 + 0x10))(0,0,0,0);
    }
  }
  if (DAT_803dce05 != '\0') {
    FUN_80070ed4();
  }
  FUN_8008faf4();
  (**(code **)(*DAT_803dca5c + 0x10))(0);
  DAT_803dcdf0 = 0;
  FUN_800898c8(0,&local_27c,(int)&local_27c + 1,(int)&local_27c + 2);
  FUN_80259ea4(0,1,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  local_288 = local_27c;
  FUN_80259b88(0,&local_288);
  FUN_80259e58(1);
  FUN_8005bc88(0,&DAT_8030e65c);
  FUN_8003fc60();
  FUN_8005bac0(auStack632);
  cVar3 = FUN_8000e620();
  if ((cVar3 != '\0') || (DAT_803dcdf7 != '\0')) {
    FUN_8007ad10((double)FLOAT_803db62c);
  }
  iVar2 = FUN_8002073c();
  if (iVar2 == 0) {
    FUN_8006c830();
  }
  if (DAT_803dcdf4 != '\0') {
    FUN_8007b01c((double)FLOAT_803dce50,(double)FLOAT_803dce4c,(double)FLOAT_803dce48,DAT_803dcdf5,
                 DAT_803dcdfb);
  }
  if (DAT_803dcdfc != 0) {
    FUN_8007a71c(DAT_803dcdfc & 0xff);
  }
  puVar5 = &DAT_803821d4;
  for (iVar2 = 0; iVar2 < DAT_803dcdf0; iVar2 = iVar2 + 1) {
    (**(code **)(*DAT_803dca7c + 0x1c))(0,0,0,1,*puVar5);
    FUN_8003b958(0,0,0,0,*puVar5,1);
    puVar5 = puVar5 + 1;
  }
  FUN_8009ece4();
  FUN_8005bc88(1,&DAT_8030e66c);
  FUN_8005bc88(2,&DAT_8030e66c);
  if (DAT_803dce30 == 1000) {
    FUN_8005db38();
    DAT_803dce30 = 0;
  }
  iVar2 = DAT_803dce30;
  (&DAT_8037e0c8)[DAT_803dce30 * 4] = 0x78000000;
  (&DAT_8037e0cc)[iVar2 * 4] = 8;
  DAT_803dce30 = DAT_803dce30 + 1;
  if (DAT_803dce30 == 1000) {
    FUN_8005db38();
    DAT_803dce30 = 0;
  }
  iVar2 = DAT_803dce30;
  (&DAT_8037e0c8)[DAT_803dce30 * 4] = 0x50000000;
  (&DAT_8037e0cc)[iVar2 * 4] = 9;
  DAT_803dce30 = DAT_803dce30 + 1;
  FUN_8005db38();
  (**(code **)(*DAT_803dca7c + 0x30))(auStack632);
  (**(code **)(*DAT_803dca7c + 0x1c))(0,0,0,0,0);
  iVar2 = FUN_8002b9ec();
  if (iVar2 != 0) {
    iVar6 = iVar2;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar2 + 0xeb); iVar4 = iVar4 + 1) {
      if (*(short *)(*(int *)(iVar6 + 200) + 0x44) == 0x2d) {
        (**(code **)(**(int **)(*(int *)(iVar6 + 200) + 0x68) + 0x2c))();
      }
      iVar6 = iVar6 + 4;
    }
  }
  FUN_8016dbf4();
  (**(code **)(*DAT_803dca60 + 0x14))(0);
  if (DAT_803dcdf6 != '\0') {
    FUN_8006c830();
    FUN_800722b0((double)FLOAT_803dce44,(double)FLOAT_803dce3c,&DAT_803821c8,&DAT_803dce40);
  }
  FUN_8005fe28();
  (**(code **)(*DAT_803dca50 + 0x58))(0,0,0,0);
  if (DAT_803dcdf8 == '\0') {
    if (DAT_803dcdf9 != '\0') {
      FUN_800717fc();
    }
  }
  else {
    FUN_80071d54(&DAT_803db630);
  }
  if (DAT_803dcdfa != '\0') {
    FUN_80079a64((double)FLOAT_803dec14,(double)FLOAT_803dec18,0x40,0);
  }
  if (DAT_803dce38 == 1) {
    FUN_80071d54(&DAT_803db630);
  }
  FUN_800628d8(0);
  return;
}

