#include "main/asset_load.h"
#include "main/dll/cloudaction_interface.h"
#include "main/mldf_fileid.h"
#include "main/model_engine.h"
#include "main/mm.h"
#include "main/newclouds.h"
#include "main/pi_dolphin.h"
#include "main/render_envfx_api.h"
#include "main/render_internal.h"
#include "main/render_lactions_api.h"
#include "main/render_mode_api.h"
#include "main/render_sequence_api.h"
#include "main/sky_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"

const int lbl_802C18C0[89] = {
    0x4, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE,
    0x10, 0x11, 0x13, 0x15, 0x17, 0x19, 0x1C, 0x1F,
    0x22, 0x25, 0x29, 0x2D, 0x32, 0x37, 0x3C, 0x42,
    0x49, 0x50, 0x58, 0x61, 0x6B, 0x76, 0x82, 0x8F,
    0x9D, 0xAD, 0xBE, 0xD1, 0xE6, 0xFD, 0x117, 0x133,
    0x151, 0x173, 0x198, 0x1C1, 0x1EE, 0x220, 0x256, 0x292,
    0x2D4, 0x31C, 0x36C, 0x3C3, 0x424, 0x48E, 0x502, 0x583,
    0x610, 0x6AB, 0x756, 0x812, 0x8E0, 0x9C3, 0xABD, 0xBD0,
    0xCFF, 0xE4C, 0xFBA, 0x114C, 0x1307, 0x14EE, 0x1706, 0x1954,
    0x1BDC, 0x1EA5, 0x21B6, 0x2515, 0x28CA, 0x2CDF, 0x315B, 0x364B,
    0x3BB9, 0x41B2, 0x4844, 0x4F7E, 0x5771, 0x602F, 0x69CE, 0x7462,
    0x7FFF};
const int lbl_802C1A24[17] = {-4, -2, -1, -1, 2, 4, 6, 8, -4, -2, -1, -1, 2, 4, 6, 8, 0};

f32 gRenderSinTable[513] = {
    0.0f, 0.003068000078201294f, 0.006136000156402588f, 0.009204000234603882f, 0.012272000312805176f, 0.015339000150561333f, 0.018407000228762627f, 0.021474000066518784f,
    0.02454099990427494f, 0.027607999742031097f, 0.030674999579787254f, 0.03374100103974342f, 0.03680700063705444f, 0.03987300023436546f, 0.042938001453876495f, 0.04600299894809723f,
    0.04906800016760826f, 0.05213199928402901f, 0.055195000022649765f, 0.05825800076127052f, 0.06132100149989128f, 0.06438300013542175f, 0.06744399666786194f, 0.07050500065088272f,
    0.07356499880552292f, 0.07662399858236313f, 0.07968199998140335f, 0.08274000138044357f, 0.08579699695110321f, 0.08885399997234344f, 0.0919089987874031f, 0.09496299922466278f,
    0.09801699966192245f, 0.10107000172138214f, 0.10412199795246124f, 0.10717199742794037f, 0.1102219969034195f, 0.11327099800109863f, 0.11631900072097778f, 0.11936499923467636f,
    0.12241099774837494f, 0.12545500695705414f, 0.12849800288677216f, 0.13154000043869019f, 0.13458099961280823f, 0.1376200020313263f, 0.14065800607204437f, 0.14369499683380127f,
    0.14673000574111938f, 0.1497649997472763f, 0.15279699862003326f, 0.15582799911499023f, 0.15885800123214722f, 0.16188600659370422f, 0.16491299867630005f, 0.1679379940032959f,
    0.17096200585365295f, 0.17398400604724884f, 0.17700399458408356f, 0.18002299964427948f, 0.18303999304771423f, 0.1860550045967102f, 0.189069002866745f, 0.19208000600337982f,
    0.19508999586105347f, 0.19809800386428833f, 0.201104998588562f, 0.20410899817943573f, 0.20711100101470947f, 0.21011200547218323f, 0.21310999989509583f, 0.21610699594020844f,
    0.21910099685192108f, 0.22209399938583374f, 0.22508400678634644f, 0.22807200253009796f, 0.2310580015182495f, 0.2340420037508011f, 0.2370239943265915f, 0.24000300467014313f,
    0.2429800033569336f, 0.24595500528812408f, 0.2489279955625534f, 0.25189799070358276f, 0.25486600399017334f, 0.25783100724220276f, 0.2607940137386322f, 0.2637549936771393f,
    0.2667129933834076f, 0.26966801285743713f, 0.2726210057735443f, 0.2755720019340515f, 0.27851998805999756f, 0.28146499395370483f, 0.28440800309181213f, 0.2873469889163971f,
    0.29028499126434326f, 0.2932190001010895f, 0.2961510121822357f, 0.2990800142288208f, 0.3020060062408447f, 0.3049289882183075f, 0.3078500032424927f, 0.3107669949531555f,
    0.3136819899082184f, 0.3165929913520813f, 0.31950199604034424f, 0.322407990694046f, 0.32530999183654785f, 0.3282099962234497f, 0.3311060070991516f, 0.33399999141693115f,
    0.33689001202583313f, 0.33977699279785156f, 0.3426609933376312f, 0.34554100036621094f, 0.3484190106391907f, 0.35129299759864807f, 0.3541640043258667f, 0.357030987739563f,
    0.3598949909210205f, 0.36275601387023926f, 0.36561301350593567f, 0.3684670031070709f, 0.3713169991970062f, 0.37416398525238037f, 0.37700700759887695f, 0.37984699010849f,
    0.38268300890922546f, 0.3855159878730774f, 0.38834500312805176f, 0.3911699950695038f, 0.39399200677871704f, 0.39680999517440796f, 0.3996239900588989f, 0.4024350047111511f,
    0.4052410125732422f, 0.4080440104007721f, 0.41084301471710205f, 0.41363799571990967f, 0.4164299964904785f, 0.41921699047088623f, 0.421999990940094f, 0.424780011177063f,
    0.42755499482154846f, 0.43032601475715637f, 0.43309399485588074f, 0.43585699796676636f, 0.438616007566452f, 0.44137099385261536f, 0.44412198662757874f, 0.44686898589134216f,
    0.44961100816726685f, 0.452349990606308f, 0.4550839960575104f, 0.45781299471855164f, 0.4605390131473541f, 0.4632599949836731f, 0.4659770131111145f, 0.4686889946460724f,
    0.4713970124721527f, 0.4740999937057495f, 0.47679901123046875f, 0.47949400544166565f, 0.4821839928627014f, 0.48486900329589844f, 0.4875499904155731f, 0.49022701382637024f,
    0.49289798736572266f, 0.4955649971961975f, 0.4982280135154724f, 0.500885009765625f, 0.5035380125045776f, 0.5061870217323303f, 0.5088300108909607f, 0.5114690065383911f,
    0.5141029953956604f, 0.5167319774627686f, 0.5193560123443604f, 0.5219749808311462f, 0.524590015411377f, 0.5271989703178406f, 0.529803991317749f, 0.5324029922485352f,
    0.5349979996681213f, 0.5375869870185852f, 0.5401719808578491f, 0.5427510142326355f, 0.545324981212616f, 0.5478940010070801f, 0.5504580140113831f, 0.5530170202255249f,
    0.5555700063705444f, 0.558118999004364f, 0.5606619715690613f, 0.563198983669281f, 0.5657320022583008f, 0.5682590007781982f, 0.5707809925079346f, 0.5732970237731934f,
    0.5758079886436462f, 0.5783140063285828f, 0.580814003944397f, 0.58330899477005f, 0.5857980251312256f, 0.5882819890975952f, 0.5907599925994873f, 0.5932319760322571f,
    0.5956990122795105f, 0.598160982131958f, 0.6006159782409668f, 0.6030669808387756f, 0.6055110096931458f, 0.60794997215271f, 0.6103829741477966f, 0.6128100156784058f,
    0.615231990814209f, 0.6176469922065735f, 0.6200569868087769f, 0.6224610209465027f, 0.6248599886894226f, 0.6272519826889038f, 0.6296380162239075f, 0.6320189833641052f,
    0.6343929767608643f, 0.6367620229721069f, 0.6391239762306213f, 0.6414809823036194f, 0.6438320279121399f, 0.6461759805679321f, 0.6485139727592468f, 0.6508470177650452f,
    0.65317302942276f, 0.6554930210113525f, 0.6578069925308228f, 0.6601139903068542f, 0.6624159812927246f, 0.6647109985351562f, 0.6669999957084656f, 0.6692829728126526f,
    0.6715589761734009f, 0.6738290190696716f, 0.6760929822921753f, 0.6783499717712402f, 0.6806010007858276f, 0.6828460097312927f, 0.6850839853286743f, 0.6873149871826172f,
    0.6895409822463989f, 0.6917589902877808f, 0.6939709782600403f, 0.6961770057678223f, 0.6983759999275208f, 0.7005689740180969f, 0.7027549743652344f, 0.7049340009689331f,
    0.7071070075035095f, 0.7092729806900024f, 0.7114319801330566f, 0.7135850191116333f, 0.7157310247421265f, 0.7178699970245361f, 0.7200030088424683f, 0.7221279740333557f,
    0.7242469787597656f, 0.7263590097427368f, 0.7284640073776245f, 0.7305629849433899f, 0.7326539754867554f, 0.7347390055656433f, 0.7368170022964478f, 0.7388870120048523f,
    0.7409510016441345f, 0.743008017539978f, 0.745058000087738f, 0.7471010088920593f, 0.7491359710693359f, 0.751164972782135f, 0.7531870007514954f, 0.755200982093811f,
    0.7572090029716492f, 0.7592089772224426f, 0.7612019777297974f, 0.7631880044937134f, 0.7651669979095459f, 0.7671390175819397f, 0.7691029906272888f, 0.7710610032081604f,
    0.7730100154876709f, 0.7749530076980591f, 0.7768880128860474f, 0.7788159847259521f, 0.7807369828224182f, 0.7826510071754456f, 0.7845569849014282f, 0.786454975605011f,
    0.788345992565155f, 0.7902299761772156f, 0.7921069860458374f, 0.7939749956130981f, 0.7958369851112366f, 0.7976909875869751f, 0.7995370030403137f, 0.8013759851455688f,
    0.8032079935073853f, 0.8050310015678406f, 0.8068479895591736f, 0.8086559772491455f, 0.8104569911956787f, 0.8122509717941284f, 0.8140360116958618f, 0.8158140182495117f,
    0.8175849914550781f, 0.8193479776382446f, 0.8211020231246948f, 0.8228499889373779f, 0.8245890140533447f, 0.826321005821228f, 0.8280450105667114f, 0.8297610282897949f,
    0.8314700126647949f, 0.8331699967384338f, 0.834863007068634f, 0.8365479707717896f, 0.8382250070571899f, 0.8398939967155457f, 0.8415549993515015f, 0.8432080149650574f,
    0.8448539972305298f, 0.8464909791946411f, 0.8481199741363525f, 0.8497419953346252f, 0.8513550162315369f, 0.852961003780365f, 0.854557991027832f, 0.8561469912528992f,
    0.8577290177345276f, 0.8593019843101501f, 0.8608670234680176f, 0.8624240159988403f, 0.8639730215072632f, 0.8655139803886414f, 0.8670459985733032f, 0.8685709834098816f,
    0.8700870275497437f, 0.871595025062561f, 0.8730949759483337f, 0.8745869994163513f, 0.8760700225830078f, 0.8775449991226196f, 0.8790119886398315f, 0.8804709911346436f,
    0.8819209933280945f, 0.8833630084991455f, 0.8847969770431519f, 0.8862220048904419f, 0.8876399993896484f, 0.8890479803085327f, 0.8904489874839783f, 0.8918409943580627f,
    0.8932240009307861f, 0.8945990204811096f, 0.8959659934043884f, 0.8973249793052673f, 0.8986740112304688f, 0.9000160098075867f, 0.9013490080833435f, 0.9026730060577393f,
    0.9039890170097351f, 0.9052969813346863f, 0.9065960049629211f, 0.9078860282897949f, 0.909168004989624f, 0.910440981388092f, 0.9117059707641602f, 0.912962019443512f,
    0.9142100214958191f, 0.9154490232467651f, 0.9166790246963501f, 0.9179009795188904f, 0.9191139936447144f, 0.9203180074691772f, 0.9215139746665955f, 0.9227010011672974f,
    0.9238799810409546f, 0.9250490069389343f, 0.9262099862098694f, 0.9273629784584045f, 0.9285060167312622f, 0.9296410083770752f, 0.9307669997215271f, 0.9318839907646179f,
    0.9329929947853088f, 0.9340929985046387f, 0.9351840019226074f, 0.9362660050392151f, 0.9373390078544617f, 0.9384040236473083f, 0.9394590258598328f, 0.9405059814453125f,
    0.9415439963340759f, 0.9425730109214783f, 0.9435939788818359f, 0.9446049928665161f, 0.9456070065498352f, 0.9466009736061096f, 0.9475859999656677f, 0.9485610127449036f,
    0.9495279788970947f, 0.9504860043525696f, 0.9514350295066833f, 0.9523749947547913f, 0.9533060193061829f, 0.9542279839515686f, 0.955141007900238f, 0.9560449719429016f,
    0.9569399952888489f, 0.9578260183334351f, 0.9587029814720154f, 0.9595710039138794f, 0.9604309797286987f, 0.9612799882888794f, 0.9621210098266602f, 0.9629529714584351f,
    0.9637759923934937f, 0.9645900130271912f, 0.9653940200805664f, 0.966189980506897f, 0.9669770002365112f, 0.9677540063858032f, 0.9685220122337341f, 0.969281017780304f,
    0.9700310230255127f, 0.9707720279693604f, 0.9715039730072021f, 0.9722269773483276f, 0.9729400277137756f, 0.9736440181732178f, 0.9743390083312988f, 0.9750249981880188f,
    0.9757019877433777f, 0.9763699769973755f, 0.9770280122756958f, 0.9776769876480103f, 0.9783170223236084f, 0.9789479970932007f, 0.9795699715614319f, 0.9801819920539856f,
    0.9807850122451782f, 0.981378972530365f, 0.9819639921188354f, 0.9825389981269836f, 0.9831050038337708f, 0.9836620092391968f, 0.9842100143432617f, 0.9847480058670044f,
    0.9852780103683472f, 0.9857980012893677f, 0.9863079786300659f, 0.9868090152740479f, 0.9873009920120239f, 0.9877840280532837f, 0.9882580041885376f, 0.988722026348114f,
    0.9891769886016846f, 0.9896219968795776f, 0.9900580048561096f, 0.9904850125312805f, 0.9909030199050903f, 0.9913110136985779f, 0.9917100071907043f, 0.9920989871025085f,
    0.9924799799919128f, 0.9928500056266785f, 0.9932119846343994f, 0.9935640096664429f, 0.9939069747924805f, 0.9942399859428406f, 0.9945650100708008f, 0.9948790073394775f,
    0.9951850175857544f, 0.995481014251709f, 0.9957669973373413f, 0.9960449934005737f, 0.9963129758834839f, 0.9965710043907166f, 0.9968199729919434f, 0.9970600008964539f,
    0.9972900152206421f, 0.9975110292434692f, 0.9977229833602905f, 0.9979249835014343f, 0.998117983341217f, 0.9983019828796387f, 0.9984760284423828f, 0.9986400008201599f,
    0.9987949728965759f, 0.9989410042762756f, 0.9990779757499695f, 0.9992049932479858f, 0.9993219971656799f, 0.9994310140609741f, 0.9995290040969849f, 0.9996190071105957f,
    0.9996989965438843f, 0.9997689723968506f, 0.9998310208320618f, 0.9998819828033447f, 0.9999250173568726f, 0.9999579787254333f, 0.9999809861183167f, 0.9999949932098389f,
    1.0f};
#pragma explicit_zero_data on
u8 lbl_802C3564[0x1964] = {0};
#pragma explicit_zero_data off

typedef struct EnvfxActEntry {
    u8 pad0[0x2a];
    u16 field_2a;
    u8 pad1[0x30];
    u8 kind;
    u8 pad2[3];
} EnvfxActEntry;

int getLActions(int a, int b, u16 idx)
{
    void* buf = mmAlloc(0x28, -1, 0);
    getTabEntry(buf, MLDF_FILEID_LACTIONS_BIN, idx * 0x28, 0x28);
    mm_free(buf);
    return 0;
}

u8* modelRenderFn_80006744(u8* p, int count, ModelRenderInstrsState* state, int gap, u8 bw)
{
    int acc;
    int bitWidth = bw;
    int idx;
    int initialBit;
    int sh16;
    int shamt = bitWidth - 4;
    int hi = (*p >> 4) & 0xf;
    int i;

    if (shamt < 0)
    {
        shamt = 0;
    }
    hi = hi << shamt;
    acc = hi;
    {
        int lo = *(u8*)p;
        p = p + 1;
        idx = (lo & 0xf) << 3;
    }
    initialBit = modelRenderInstrsState_getBit(state);
    gap = gap - bitWidth;
    sh16 = 0x10 - bitWidth;

    for (i = count / 2; i > 0; i--)
    {
        {
            u8 nib = *p & 0xf;
            int base = lbl_802C18C0[idx];
            int delta = 0;
            if (nib & 1)
            {
                delta = base >> 2;
            }
            if (nib & 2)
            {
                delta += base >> 1;
            }
            if (nib & 4)
            {
                delta += base;
            }
            if (nib & 8)
            {
                delta = -delta;
            }
            acc += delta;
            idx += lbl_802C1A24[nib];
            if (idx < 0)
            {
                idx = 0;
            }
            else if (idx > 0x58)
            {
                idx = 0x58;
            }
            {
                u32 packed = (u16)acc;
                int curBit = state->bit;
                int bo = curBit >> 3;
                u8* dp;
                packed <<= ((8 - (curBit & 7)) + sh16);
                dp = (u8*)state->instrs;
                dp[bo] |= (packed >> 16) & 0xff;
                dp = (u8*)state->instrs;
                dp[bo + 1] |= (packed >> 8) & 0xff;
                dp = (u8*)state->instrs;
                dp[bo + 2] |= packed & 0xff;
                state->bit += bitWidth;
                state->bit += gap;
            }
        }
        {
            u8 nib = (*p++ >> 4) & 0xf;
            int base = lbl_802C18C0[idx];
            int delta = 0;
            if (nib & 1)
            {
                delta = base >> 2;
            }
            if (nib & 2)
            {
                delta += base >> 1;
            }
            if (nib & 4)
            {
                delta += base;
            }
            if (nib & 8)
            {
                delta = -delta;
            }
            acc += delta;
            idx += lbl_802C1A24[nib];
            if (idx < 0)
            {
                idx = 0;
            }
            else if (idx > 0x58)
            {
                idx = 0x58;
            }
            {
                u32 packed = (u16)acc;
                int curBit = state->bit;
                int bo = curBit >> 3;
                u8* dp;
                packed <<= ((8 - (curBit & 7)) + sh16);
                dp = (u8*)state->instrs;
                dp[bo] |= (packed >> 16) & 0xff;
                dp = (u8*)state->instrs;
                dp[bo + 1] |= (packed >> 8) & 0xff;
                dp = (u8*)state->instrs;
                dp[bo + 2] |= packed & 0xff;
                state->bit += bitWidth;
                state->bit += gap;
            }
        }
    }
    if (count & 1)
    {
        u8 nib = *p++ & 0xf;
        int base = lbl_802C18C0[idx];
        int delta = 0;
        if (nib & 1)
        {
            delta = base >> 2;
        }
        if (nib & 2)
        {
            delta += base >> 1;
        }
        if (nib & 4)
        {
            delta += base;
        }
        if (nib & 8)
        {
            delta = -delta;
        }
        acc += delta;
        idx += lbl_802C1A24[nib];
        if (idx < 0)
        {
            idx = 0;
        }
        else if (idx > 0x58)
        {
            idx = 0x58;
        }
        {
            u32 packed = (u16)acc;
            int curBit = state->bit;
            int bo = curBit >> 3;
            u8* dp;
            packed <<= ((8 - (curBit & 7)) + sh16);
            dp = (u8*)state->instrs;
            dp[bo] |= (packed >> 16) & 0xff;
            dp = (u8*)state->instrs;
            dp[bo + 1] |= (packed >> 8) & 0xff;
            dp = (u8*)state->instrs;
            dp[bo + 2] |= packed & 0xff;
            state->bit += bitWidth;
        }
    }
    if (gap != 0)
    {
        modelRenderInstrsState_setBit(state, initialBit + bitWidth);
    }
    return p;
}

int fn_80006B1C(ModelRenderInstrsState* src, ModelRenderInstrsState* dst, int count, int gap, u8 bitWidth)
{
    int startBit = modelRenderInstrsState_getBit(dst);
    u32 mask;
    int sh16;
    int i;
    int bw = bitWidth;

    mask = ~(-1 << bw);
    sh16 = 0x10 - bw;
    for (i = 0; i < count; i++)
    {
        int sByte;
        int sbit = src->bit;
        u32 val;
        u8* sp;
        u8* dp;
        int curBit;
        u32 packed;
        sByte = sbit >> 3;
        sp = (u8*)src->instrs + sByte;
        val = sp[0] << 16;
        val = val | (sp[1] << 8);
        val = val | sp[2];
        src->bit = sbit + bw;
        packed = mask & (val >> (sbit & 7));
        curBit = dst->bit;
        sByte = curBit >> 3;
        packed = packed << ((8 - (curBit & 7)) + sh16);
        dp = (u8*)dst->instrs;
        dp[sByte] |= (packed >> 16) & 0xff;
        dp = (u8*)dst->instrs;
        dp[sByte + 1] |= (packed >> 8) & 0xff;
        dp = (u8*)dst->instrs;
        dp[sByte + 2] |= packed & 0xff;
        dst->bit += bw;
        dst->bit += gap;
    }
    modelRenderInstrsState_setBit(dst, startBit + bw);
    {
        u8* base = (u8*)src->instrs;
        return base[(src->bit >> 3) + 1];
    }
}

/* Refill the two parallel 64-bit bitstream windows from the next
   byte-aligned position once the consumed bit count overruns 64. */
#define RENDER_BITS_REFILL(nb)                                                                                         \
    bitpos -= (nb);                                                                                                    \
    bufA = bitpos >> 3;                                                                                                \
    posA += bufA;                                                                                                      \
    addrB = bufA + curB;                                                                                               \
    curB = addrB;                                                                                                      \
    bitpos &= 7;                                                                                                       \
    render_copyPackedU64Head(&bufA, posA);                                                                             \
    render_copyPackedU64Tail(&bufA, posA + 7);                                                                         \
    render_copyPackedU64Head(&bufB, addrB);                                                                            \
    render_copyPackedU64Tail(&bufB, addrB + 7);                                                                        \
    bufA <<= (bitpos & 0xFFFFFFFF);                                                                                    \
    bufB <<= (bitpos & 0xFFFFFFFF);                                                                                    \
    bitpos += (nb);

void fn_80007F78(u8* anim, u16* dst, u16* out)
{
    f32 t = *(f32*)(anim + 0x4);
    u64 end;
    u64 outPos = (u32)out;
    int curB = *(u16*)(anim + 0x4c);
    u64 posA = *(u32*)(anim + 0x2c);
    u64 tp = *(u32*)(anim + 0x34) + 4;
    u64 bufA;
    u64 bufB;
    s64 tmp;
    s64* q = &tmp;
    u64 bitpos;
    u64 vA;
    u32 addrB;
    u64 maskConst = 0xFFF0;
    int i;
    union
    {
        s64 v;
        int w[2];
    } frac;

    addrB = posA + curB;
    end = (u32)(dst + 3);
    t = t - floorf(t);
    t = t * lbl_803DE544;
    frac.v = (int)t;

    render_copyPackedU64Head(&bufA, posA);
    render_copyPackedU64Tail(&bufA, posA + 7);
    render_copyPackedU64Head(&bufB, addrB);
    render_copyPackedU64Tail(&bufB, addrB + 7);
    bitpos = 0;

    do
    {
        u64 sample = 0;
        u64 h = *(u16*)(u32)tp;
        u64 nib = h & 0xf;
        u32 hw = h;
        u64 masked = h & maskConst;

        if (nib != 0)
        {
            bitpos += nib;
            if ((s64)bitpos > 64)
            {
                RENDER_BITS_REFILL(nib)
            }
            tmp = 64 - nib;
            vA = bufA >> (tmp & 0xFFFFFFFF);
            tmp = bufB >> (tmp & 0xFFFFFFFF);
            tmp = tmp - vA;
            tmp = tmp << 50;
            for (i = 50; i != 0; i--)
            {
                *q /= 2;
            }
            tmp = tmp * frac.v;
            for (i = 14; i != 0; i--)
            {
                *q /= 2;
            }
            sample = masked + ((vA + tmp) << 2);
            bufA <<= (nib & 0xFFFFFFFF);
            bufB <<= (nib & 0xFFFFFFFF);
        }
        tp += 2;
        *(u16*)(u32)outPos = sample;
        outPos += 2;

        sample = 0;
        if (hw & 0x10)
        {
            u64 nib3;

            h = *(u16*)(u32)tp;
            if ((h & 0x10) != 0)
            {
                u64 nib2 = h & 0xf;
                if (nib2 != 0)
                {
                    bitpos += nib2;
                    if ((s64)bitpos > 64)
                    {
                        RENDER_BITS_REFILL(nib2)
                    }
                    bufA <<= (nib2 & 0xFFFFFFFF);
                    bufB <<= (nib2 & 0xFFFFFFFF);
                }
                tp += 2;
                if (!((u32)h & 0x20))
                {
                    goto storeSecond;
                }
                h = *(u16*)(u32)tp;
            }
            nib3 = h & 0xf;
            if (nib3 != 0)
            {
                u64 masked2 = h & 0xFFF0;
                bitpos += nib3;
                if ((s64)bitpos > 64)
                {
                    RENDER_BITS_REFILL(nib3)
                }
                tmp = 64 - nib3;
                vA = bufA >> (tmp & 0xFFFFFFFF);
                tmp = bufB >> (tmp & 0xFFFFFFFF);
                tmp = tmp - vA;
                tmp = tmp * frac.v;
                for (i = 14; i != 0; i--)
                {
                    *q /= 2;
                }
                sample = masked2 + (vA + tmp);
                bufA <<= (nib3 & 0xFFFFFFFF);
                bufB <<= (nib3 & 0xFFFFFFFF);
            }
            tp += 2;
        }
    storeSecond:
        *dst = sample;
        dst++;
    } while ((u64)(u32)dst != end);
}

#pragma dont_inline on
void render_copyPackedU64Tail(u64* dst, u32 packed)
{
    /* Preserve the leading bytes of *dst; fill the tail from the aligned
       64-bit word shifted down. */
    u64 src = *(u64*)(packed & ~7);

    switch (packed & 7)
    {
    case 7:
        *dst = src;
        break;
    case 6:
        *dst = (*dst & 0xff00000000000000ULL) | (src >> 8);
        break;
    case 5:
        *dst = (*dst & 0xffff000000000000ULL) | (src >> 16);
        break;
    case 4:
        *dst = (*dst & 0xffffff0000000000ULL) | (src >> 24);
        break;
    case 3:
        *dst = (*dst & 0xffffffff00000000ULL) | (src >> 32);
        break;
    case 2:
        *dst = (*dst & 0xffffffffff000000ULL) | (src >> 40);
        break;
    case 1:
        *dst = (*dst & 0xffffffffffff0000ULL) | (src >> 48);
        break;
    case 0:
        *dst = (*dst & 0xffffffffffffff00ULL) | (src >> 56);
        break;
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void render_copyPackedU64Head(u64* dst, u32 packed)
{
    /* Fill the head from the aligned 64-bit word; preserve bytes after the
       unaligned source offset. */
    u64 src = *(u64*)(packed & ~7);

    switch (packed & 7)
    {
    case 0:
        *dst = src;
        break;
    case 1:
        *dst = (*dst & 0xffULL) | (src << 8);
        break;
    case 2:
        *dst = (*dst & 0xffffULL) | (src << 16);
        break;
    case 3:
        *dst = (*dst & 0xffffffULL) | (src << 24);
        break;
    case 4:
        *dst = (*dst & 0xffffffffULL) | (src << 32);
        break;
    case 5:
        *dst = (*dst & 0xffffffffffULL) | (src << 40);
        break;
    case 6:
        *dst = (*dst & 0xffffffffffffULL) | (src << 48);
        break;
    case 7:
        *dst = (*dst & 0xffffffffffffffULL) | (src << 56);
        break;
    }
}
#pragma dont_inline reset

s16 renderModeSetOrGet(int mode)
{
    if (mode != -1)
    {
        gRenderMode = mode;
        return mode;
    }
    return gRenderMode;
}

int return0xFFFF_80008B6C(void)
{
    return -0x1;
}

int getEnvfxActImmediately(struct GameObject* a, struct GameObject* b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry* e = (EnvfxActEntry*)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, MLDF_FILEID_ENVFXACT_BIN, idx * 0x60, 0x60);
    if (e != NULL)
    {
        if (e->kind <= 2 || e->kind == 4)
        {
            (*gNewCloudsInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 3)
        {
            e->field_2a = 0;
            (*gSky2Interface)->updateEnvfxAct(a, b, e, d, idx);
        }
        else if (e->kind == 5)
        {
            e->field_2a = 0;
            (*gSkyInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 6)
        {
            (*gCloudActionInterface)->updateEnvfxAct(a, b, e, d, idx);
        }
    }
    return 0;
}

int getEnvfxAct(struct GameObject* a, struct GameObject* b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry* e = (EnvfxActEntry*)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, MLDF_FILEID_ENVFXACT_BIN, idx * 0x60, 0x60);
    if (e != NULL)
    {
        if (e->kind <= 2 || e->kind == 4)
        {
            (*gNewCloudsInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 3)
        {
            (*gSky2Interface)->updateEnvfxAct(a, b, e, d, idx);
        }
        else if (e->kind == 5)
        {
            (*gSkyInterface)->updateEnvfxAct(a, b, e, d);
        }
        else if (e->kind == 6)
        {
            (*gCloudActionInterface)->updateEnvfxAct(a, b, e, d, idx);
        }
    }
    return 0;
}
