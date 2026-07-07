/*
 * DLL 0xE9 - SetupPoint [8016B230-8016B2E0)
 *
 * The DLL's own canonical code is just setuppoint_init, an empty
 * load-time hook. (The v1.0 "drift" catalogue of foreign ObjectDescriptor
 * registration tables that previously accreted in this translation unit
 * has been dropped; each of those descriptors is defined by its own DLL.)
 */

void setuppoint_init(void)
{
}
