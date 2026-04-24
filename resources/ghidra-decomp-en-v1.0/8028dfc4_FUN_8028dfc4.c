// Function: FUN_8028dfc4
// Entry: 8028dfc4
// Size: 832 bytes

void FUN_8028dfc4(undefined4 *param_1,ushort param_2)

{
  undefined auStack200 [44];
  undefined auStack156 [44];
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 local_48;
  undefined auStack68 [56];
  
  switch(param_2) {
  case 0:
    FUN_8028e304(param_1,&DAT_802c2adc,0);
    break;
  case 1:
    FUN_8028e304(param_1,&DAT_802c2ade,0);
    break;
  case 2:
    FUN_8028e304(param_1,&DAT_802c2ae0,0);
    break;
  case 3:
    FUN_8028e304(param_1,&DAT_802c2ae2,0);
    break;
  case 4:
    FUN_8028e304(param_1,&DAT_802c2ae4,1);
    break;
  case 5:
    FUN_8028e304(param_1,&DAT_802c2ae7,1);
    break;
  case 6:
    FUN_8028e304(param_1,&DAT_802c2aea,1);
    break;
  case 7:
    FUN_8028e304(param_1,&DAT_802c2aed,2);
    break;
  case 8:
    FUN_8028e304(param_1,&DAT_802c2af1,2);
    break;
  case 0xffffffc0:
    FUN_8028e304(param_1,s_54210108624275221700372640043497_802c2a3d,0xffffffec);
    break;
  default:
    FUN_8028dfc4(auStack68,(int)((short)param_2 / 2));
    FUN_8028e3f0(param_1,auStack68,auStack68);
    if ((param_2 & 1) != 0) {
      local_70 = *param_1;
      local_6c = param_1[1];
      local_68 = param_1[2];
      local_64 = param_1[3];
      local_60 = param_1[4];
      local_5c = param_1[5];
      local_58 = param_1[6];
      local_54 = param_1[7];
      local_50 = param_1[8];
      local_4c = param_1[9];
      local_48 = *(undefined2 *)(param_1 + 10);
      if ((short)param_2 < 1) {
        FUN_8028e304(auStack200,&DAT_802c2ada,0xffffffff);
        FUN_8028e3f0(param_1,&local_70,auStack200);
      }
      else {
        FUN_8028e304(auStack156,&DAT_802c2ade,0);
        FUN_8028e3f0(param_1,&local_70,auStack156);
      }
    }
    break;
  case 0xffffffcb:
    FUN_8028e304(param_1,s_11102230246251565404236316680908_802c2a6b,0xfffffff0);
    break;
  case 0xffffffe0:
    FUN_8028e304(param_1,s_23283064365386962890625_802c2a92,0xfffffff6);
    break;
  case 0xfffffff0:
    FUN_8028e304(param_1,s_152587890625_802c2aaa,0xfffffffb);
    break;
  case 0xfffffff8:
    FUN_8028e304(param_1,s_390625_802c2ab7,0xfffffffd);
    break;
  case 0xfffffff9:
    FUN_8028e304(param_1,s_78125_802c2abe,0xfffffffd);
    break;
  case 0xfffffffa:
    FUN_8028e304(param_1,s_15625_802c2ac4,0xfffffffe);
    break;
  case 0xfffffffb:
    FUN_8028e304(param_1,&DAT_802c2aca,0xfffffffe);
    break;
  case 0xfffffffc:
    FUN_8028e304(param_1,&DAT_802c2acf,0xfffffffe);
    break;
  case 0xfffffffd:
    FUN_8028e304(param_1,&DAT_802c2ad3,0xffffffff);
    break;
  case 0xfffffffe:
    FUN_8028e304(param_1,&DAT_802c2ad7,0xffffffff);
    break;
  case 0xffffffff:
    FUN_8028e304(param_1,&DAT_802c2ada,0xffffffff);
  }
  return;
}

