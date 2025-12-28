
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Groth16 verifier template.
/// @author Remco Bloemen
/// @notice Supports verifying Groth16 proofs. Proofs can be in uncompressed
/// (256 bytes) and compressed (128 bytes) format. A view function is provided
/// to compress proofs.
/// @notice See <https://2π.com/23/bn254-compression> for further explanation.
contract ScUpdateVerifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();
    /// The commitment is invalid
    /// @dev This can mean that provided commitment points and/or proof of knowledge are not on their
    /// curves, that pairing equation fails, or that the commitment and/or proof of knowledge is not for the
    /// commitment key.
    error CommitmentInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field Fp order P and scalar field Fr order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Extension field Fp2 = Fp[i] / (i² + 1)
    // Note: This is the complex extension field of Fp with i² = -1.
    //       Values in Fp2 are represented as a pair of Fp elements (a₀, a₁) as a₀ + a₁⋅i.
    // Note: The order of Fp2 elements is *opposite* that of the pairing contract, which
    //       expects Fp2 elements in order (a₁, a₀). This is also the order in which
    //       Fp2 elements are encoded in the public interface as this became convention.

    // Constants in Fp
    uint256 constant FRACTION_1_2_FP = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 constant FRACTION_27_82_FP = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 constant FRACTION_3_82_FP = 0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FP = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 constant EXP_SQRT_FP = 0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52; // (P + 1) / 4;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X = 11311998978998538252272299534417621918017950983251300470337065597538692557553;
    uint256 constant ALPHA_Y = 2430373605429613439646115982371784186867669797256940709615292647519536422590;

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 = 14906754947056305502118619246665004154993216882821848221885217667640343324114;
    uint256 constant BETA_NEG_X_1 = 16168303163613509818599099448897717292074219633039622464963389010547285061070;
    uint256 constant BETA_NEG_Y_0 = 4792030686727557963543120394711563826325940047780904305951758377598319867550;
    uint256 constant BETA_NEG_Y_1 = 7085623648520490924030694677478152637487406421470387754357235678388159793716;

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 = 9475197294134673661089301823693846266159324427828156137564253765483119023038;
    uint256 constant GAMMA_NEG_X_1 = 300003313413413320832931846992216639806377730096240046723725744396145714333;
    uint256 constant GAMMA_NEG_Y_0 = 12325992114405192827474183355610884411144867637197603686683443550714160650272;
    uint256 constant GAMMA_NEG_Y_1 = 4647603517382882985798100658184501251953980561091660403403756303715683502694;

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 = 13484312348395249397784625037285682234010590839922990714510235010868668834734;
    uint256 constant DELTA_NEG_X_1 = 5153038823973778006844124535445308869655724121590673635616295740301607886398;
    uint256 constant DELTA_NEG_Y_0 = 13572270891393213489770323728930178326803470446315167368235923842098511080045;
    uint256 constant DELTA_NEG_Y_1 = 2700852720663890659473004706254170160761599274463440644672482219084032564592;
    // Pedersen G point in G2 in powers of i
    uint256 constant PEDERSEN_G_X_0 = 8279171738186269955054754072103496657242789202777814237527884015245328128180;
    uint256 constant PEDERSEN_G_X_1 = 15298145196143547382260938264461718595382551510339450478875942957030274003144;
    uint256 constant PEDERSEN_G_Y_0 = 11151997430374540027433522497810707512461792196728392554258885836531375011471;
    uint256 constant PEDERSEN_G_Y_1 = 8291985989469099532295604853672438378079336351429562783544467659590601750804;

    // Pedersen GSigmaNeg point in G2 in powers of i
    uint256 constant PEDERSEN_GSIGMANEG_X_0 = 5137796145570970095845607123188577122377519832533323803400787638832712280068;
    uint256 constant PEDERSEN_GSIGMANEG_X_1 = 7954109419099789054050558915437243329963347337844596640602075792618999143393;
    uint256 constant PEDERSEN_GSIGMANEG_Y_0 = 4650219566096503379818132881012545815530417337352180822846138801566239692447;
    uint256 constant PEDERSEN_GSIGMANEG_Y_1 = 16415732184319726027334591331541887234200401807900459081884728545181820902911;

    // Constant and public input points
    uint256 constant CONSTANT_X = 782457284761172103554867782867944064294551417854276172234468244321049157892;
    uint256 constant CONSTANT_Y = 15800572918701662364020643829664704587487160554688254084060795316361397921090;
    uint256 constant PUB_0_X = 12146816076030731574051054663904025784222513756360386569988804951164582019468;
    uint256 constant PUB_0_Y = 1254721023889669590520400508353487342954442525921089364315911162170732948635;
    uint256 constant PUB_1_X = 1035702135947877099538071285435106826804649145529091895693546040027296353499;
    uint256 constant PUB_1_Y = 13849886366851484780281974834912149333041251465906803227106649094082899385793;
    uint256 constant PUB_2_X = 13106358438897695842037003707611538120635704087009206440940966726190246279851;
    uint256 constant PUB_2_Y = 20748087601089508151286021324507684164121308524225953473779545630181977958503;
    uint256 constant PUB_3_X = 14191523110006276277595049492115995627766377659609852094532554420397548586040;
    uint256 constant PUB_3_Y = 4085171558353175330466550588524065502948747454045086646996527379616552226138;
    uint256 constant PUB_4_X = 5628661300824986708227814671654460371825362595761968901493828045519730296819;
    uint256 constant PUB_4_Y = 10532765888236088663826316190297854754338636784869943215234248770718216348786;
    uint256 constant PUB_5_X = 3130085065315751584204985212312342927919635234603232981406722811018231116064;
    uint256 constant PUB_5_Y = 19110956070149383328090049712891662030666722641203020306502348154760967283547;
    uint256 constant PUB_6_X = 3658166510765972960498150006733159490392437661613388148292027208037095775904;
    uint256 constant PUB_6_Y = 2818429013887591827680533151214853319471425870481866634081361542298607320074;
    uint256 constant PUB_7_X = 17736618177599663247042385290087012061002482803676210487916076609646183708182;
    uint256 constant PUB_7_Y = 5099868257047953050675336542022262323709618026242842879474274947307927711233;
    uint256 constant PUB_8_X = 672089913238481427946653231595486932634242477412817091831590091823070411820;
    uint256 constant PUB_8_Y = 10186837681341327688570096989684769866276535818828943841019719804065462650621;
    uint256 constant PUB_9_X = 15952332550669257260811190274514556210703742324677240428155740326395497610955;
    uint256 constant PUB_9_Y = 9546057078500788281935660570325862828026854334556295206223770402002799765032;
    uint256 constant PUB_10_X = 19324108170352961076363131022050932907566521315293677181917877182417929641958;
    uint256 constant PUB_10_Y = 3235660591042435552046280188748630716032772247665949454999199147264377416685;
    uint256 constant PUB_11_X = 19618704942233576654535558858450631150509685962376538083649855757413326332369;
    uint256 constant PUB_11_Y = 5011684160487955859987284158187342818220800129418787483834512490055916486868;
    uint256 constant PUB_12_X = 8512464054705105290951826464558664450212650436393594023694879906011422418710;
    uint256 constant PUB_12_Y = 6591519128315607294828694207676939403020006580770152455814608392420205863280;
    uint256 constant PUB_13_X = 13222430730552576734560141480263797845053125890511622219059035317271660387404;
    uint256 constant PUB_13_Y = 11515181621627099678958944886489350032882980843170085635063629874044850382496;
    uint256 constant PUB_14_X = 2083650287206115799517661130755510183813709712479985639863361128738307295632;
    uint256 constant PUB_14_Y = 9322224412462189172831323404313883010416813232008528768301121779322263082452;
    uint256 constant PUB_15_X = 8993702500673191013197815786292386369486734328671530913361722255649152524531;
    uint256 constant PUB_15_Y = 2324522609803623663441303436615906445918094155446665976246521119806573154927;
    uint256 constant PUB_16_X = 20893943541008657468602647883928253531227248028228784090123932640166512624191;
    uint256 constant PUB_16_Y = 16494799000405247863149776706025136108057103175537521079883695451327965712009;
    uint256 constant PUB_17_X = 17773745038963880997988735880239104443668862838309925559676141828091362975910;
    uint256 constant PUB_17_Y = 21327711210857160153369081994074645710727689257199944494308307106529930615976;
    uint256 constant PUB_18_X = 21234907493129113525008677318489196037875429386924907020780647527647378160041;
    uint256 constant PUB_18_Y = 15679414752220425721994051854359152728221695734479658236237556466533090830289;
    uint256 constant PUB_19_X = 4334076719031975891802391590320006846973894259212431915214671410384970937658;
    uint256 constant PUB_19_Y = 18915074866880736480297817204481421848142261055078965231719082660432668328156;
    uint256 constant PUB_20_X = 12774021359119730178686173008884914142511124604464100576416731610814973486809;
    uint256 constant PUB_20_Y = 8138554902331333884993696350805699901351372902353825854038993352522166543787;
    uint256 constant PUB_21_X = 16652056047929484619207933421605158113833889222531093333490361244289081993597;
    uint256 constant PUB_21_Y = 6889025692202168446270297979201283929792793238730117262871048633231619513399;
    uint256 constant PUB_22_X = 9509699750334868811017129304821430054912859398540255071328398959957231037671;
    uint256 constant PUB_22_Y = 13068728842459064986696587558503012315031776407578562686063289045424225266013;
    uint256 constant PUB_23_X = 10313400804064260942817853105167601191154207746862328446619429843233685382284;
    uint256 constant PUB_23_Y = 14301548875503789491708384061712888069083198611517843259184226642395869490194;
    uint256 constant PUB_24_X = 16657199269168959202896906854152068993063771419776182140346073035303321756041;
    uint256 constant PUB_24_Y = 3403767753693603592134389412259333863568009832734687981721481262043091299993;
    uint256 constant PUB_25_X = 21573453674887887155728940393903965909223892130621292604365582714127478631492;
    uint256 constant PUB_25_Y = 17157113814182461198734293286734243606309937895781797256067312823276123776381;
    uint256 constant PUB_26_X = 7048727999660738055470682080773341416050894522569253016895367234010759045472;
    uint256 constant PUB_26_Y = 2627207167938271821209877453341624228713772805027681115372781254539149681791;
    uint256 constant PUB_27_X = 13956641724285064086533357938520355584636681557341361360403020652575572985960;
    uint256 constant PUB_27_Y = 11693188416723932745012187656843673869721039007479386943233330378219973286083;
    uint256 constant PUB_28_X = 9326519170421416119966313410804892926377043952944788969569010752852590640781;
    uint256 constant PUB_28_Y = 20842856598727429967342968676166811853318285554971381276000462195815368276457;
    uint256 constant PUB_29_X = 1804634968126671031316505709287452770522738720018283659713276489699321119547;
    uint256 constant PUB_29_Y = 6332393489720031998463048224561936842533001056763280137674444962603895587162;
    uint256 constant PUB_30_X = 1596027844569727908447654079320070442500233845954732355191322911399026357196;
    uint256 constant PUB_30_Y = 6816949251629615864535434322366370717895530469281358822179407334756345620714;
    uint256 constant PUB_31_X = 15780373151888559460883067279333761563567125631542527775811522439627312833647;
    uint256 constant PUB_31_Y = 2609060687556928607698000597297051226145752772783065360826407567619356087036;
    uint256 constant PUB_32_X = 14392191283277972590754093738847111431407315297301815028306681799394205157414;
    uint256 constant PUB_32_Y = 8797223515546679890529704831187115870642679288109038495695633881109051966882;
    uint256 constant PUB_33_X = 19505186724842405931174852813767913502536610737836452803714464650432660028507;
    uint256 constant PUB_33_Y = 1350444296598035820763177756401812808950265279400601690824586144052501400301;
    uint256 constant PUB_34_X = 4555046985356173452269779969231037773463148262672596132987938181234972808942;
    uint256 constant PUB_34_Y = 2826721175566024220275807110187003469754846557042013296077711339893774341784;
    uint256 constant PUB_35_X = 13960851725580147771343879433018537070012043812109705106538251390194665699695;
    uint256 constant PUB_35_Y = 530504173011406506642279796956221415288465825450670128020239219501164784841;
    uint256 constant PUB_36_X = 5893110424987693594362655156009549326980734917808434905147367843816877153140;
    uint256 constant PUB_36_Y = 676587194381018274252843791444569450403693390162432725367270861814941699362;
    uint256 constant PUB_37_X = 15313748214523583207430936628475281484787455649264585834073803151177825796058;
    uint256 constant PUB_37_Y = 1935063841778717402203673699603623292389861448823753835106908350261173957148;
    uint256 constant PUB_38_X = 830651492858900520600430471415445122319237293255000097002524804107439772871;
    uint256 constant PUB_38_Y = 4754192822836394118035187667169627292223932699304693269511231966011702051235;
    uint256 constant PUB_39_X = 20987388875496848406389779196103937639505982879349186242433637304598527009870;
    uint256 constant PUB_39_Y = 17357483134029087508823132516018537086186349405762084461470940274660016350891;
    uint256 constant PUB_40_X = 8397509316573934423093137380507086923523798589359957407053658448428422530957;
    uint256 constant PUB_40_Y = 19135096144934961143685843514891696789283666938277908999754319479061639499381;
    uint256 constant PUB_41_X = 15019138172558561383546916256344014921966408501245319849567718979029732239712;
    uint256 constant PUB_41_Y = 20860647136489295482574149356398632912585925189550869373187355794922432881168;
    uint256 constant PUB_42_X = 449252403865425468857042477032686147474579858813027466246009835362185267775;
    uint256 constant PUB_42_Y = 13281332758177366665518885189127841776138846821357946806430468798359354311377;
    uint256 constant PUB_43_X = 5230912733396224243953898151426209676402000858389514096469028544248960193902;
    uint256 constant PUB_43_Y = 11501287318055076610695757617461274764013337763982977791196242556092093726840;
    uint256 constant PUB_44_X = 9306676414096069441316133726912143840281192503497781933273353305207913424902;
    uint256 constant PUB_44_Y = 18380927337949428750479674809747848245864363773945615980156068211012892384763;
    uint256 constant PUB_45_X = 9648249065565350558647437716624784918667416115194189692285768763478802508694;
    uint256 constant PUB_45_Y = 511980609329550226499133988094053945353675874265403142272178079408783709304;
    uint256 constant PUB_46_X = 15404229431040072339280356025741117391823904133579588155143359122867192580595;
    uint256 constant PUB_46_Y = 3657712313787879271350764174041723763196897989029266884358073004183991835149;
    uint256 constant PUB_47_X = 8370278503335165160532870656361522964741499352691955166087648251640278866772;
    uint256 constant PUB_47_Y = 14263876101662455637622005656029254661989723329511091922572220526050784122853;
    uint256 constant PUB_48_X = 16096646168914216710484014116685755069534380577753364110680062355072935388413;
    uint256 constant PUB_48_Y = 20386127678263125786575802590716698247114033954323226619328556611422964849088;
    uint256 constant PUB_49_X = 5982449375614102965253103286423694974300533516793515024662524758211689365850;
    uint256 constant PUB_49_Y = 16239105284863468328797300849932496967347375609638043180405857850764748136079;
    uint256 constant PUB_50_X = 409083992341561278957818958079859790482644362009883715071371254887321712850;
    uint256 constant PUB_50_Y = 9395779039593000316897897257886623078104086753083956240325540072837231411348;
    uint256 constant PUB_51_X = 6187449436950317217447905251077091789151376302784504937264174477978032353614;
    uint256 constant PUB_51_Y = 14135035725449902294692396620709871206612397125794537551286313445909535499354;
    uint256 constant PUB_52_X = 21368103774383798883632933845869783748173756835055718650244696700194890391660;
    uint256 constant PUB_52_Y = 6239025881740691369008381751645151634788903556953725220205564623555442885409;
    uint256 constant PUB_53_X = 20785749477400093351859071504815745758220368288163347469311375748383236778997;
    uint256 constant PUB_53_Y = 9355479768136313673940868737323432401189351733206336551185429568440563741245;
    uint256 constant PUB_54_X = 8928009750425445545639656877879182817372513049411115921655619456215751078418;
    uint256 constant PUB_54_Y = 9144107055164646230207179655399070913258298428701948323918135890482541792513;
    uint256 constant PUB_55_X = 21490061728315372740290895741170326333338642464679562476570413390902820490252;
    uint256 constant PUB_55_Y = 8025979060333694216212874724850278498501680678318798239714072899728808729472;
    uint256 constant PUB_56_X = 1630932318030030091196063950394323293533451911282860516267382798965624409008;
    uint256 constant PUB_56_Y = 2597926168691128005653156760180416364576963948387137560075377571565063878952;
    uint256 constant PUB_57_X = 16307064127495321656341129828636910905787880194943794696734680097412333193601;
    uint256 constant PUB_57_Y = 1258379658217481938655347226769697979177965990221922047522152707338128327975;
    uint256 constant PUB_58_X = 13148577683322703043305401540516772408244044688555778491404448383744212679221;
    uint256 constant PUB_58_Y = 4108566377389713823839181633346199629331735827861223872793608434899243739863;
    uint256 constant PUB_59_X = 17010879093109338823811280047822213496900895143319444052568447528833424068076;
    uint256 constant PUB_59_Y = 18530187349795047874062103475623259563719135566256792400388559285105568221060;
    uint256 constant PUB_60_X = 7344688119814412014303939836376611801930439726374959936422739380491073231583;
    uint256 constant PUB_60_Y = 18758940796605180023791968814501458533259609281527501680234004446869816426374;
    uint256 constant PUB_61_X = 10796660418633285239058928131669956779790586022047844047768395433300793239473;
    uint256 constant PUB_61_Y = 11969678131661544256505334626869672802179639433171799693262422756767539296032;
    uint256 constant PUB_62_X = 13790795917821351974784204877530720508719463857239068394311111637470251969742;
    uint256 constant PUB_62_Y = 18526230795512012932722852673606926194726958438409019505841222715914693829054;
    uint256 constant PUB_63_X = 20525279563451881111268987676916689722652370572002437217072923872597628940315;
    uint256 constant PUB_63_Y = 20749513994326763643101622899614728545468739201923243557797736588528442674354;
    uint256 constant PUB_64_X = 16709499238676747723566872861674673638578789997662458102336731156747428968493;
    uint256 constant PUB_64_Y = 1812454958763751884102568274833509370455228390117531957190508395052308513666;

    /// Negation in Fp.
    /// @notice Returns a number x such that a + x = 0 in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @return x the result
    function negate(uint256 a) internal pure returns (uint256 x) {
        unchecked {
            x = (P - (a % P)) % P; // Modulo is cheaper than branching
        }
    }

    /// Exponentiation in Fp.
    /// @notice Returns a number x such that a ^ e = x in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @param e the exponent
    /// @return x the result
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    /// Invertsion in Fp.
    /// @notice Returns a number x such that a * x = 1 in Fp.
    /// @notice The input does not need to be reduced.
    /// @notice Reverts with ProofInvalid() if the inverse does not exist
    /// @param a the input
    /// @return x the solution
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    /// Square root in Fp.
    /// @notice Returns a number x such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        if (mulmod(x, x, P) != a) {
            // Square root does not exist or a is not reduced.
            // Happens when G1 point is not on curve.
            revert ProofInvalid();
        }
    }

    /// Square test in Fp.
    /// @notice Returns whether a number x exists such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function isSquare_Fp(uint256 a) internal view returns (bool) {
        uint256 x = exp(a, EXP_SQRT_FP);
        return mulmod(x, x, P) == a;
    }

    /// Square root in Fp2.
    /// @notice Fp2 is the complex extension Fp[i]/(i^2 + 1). The input is
    /// a0 + a1 ⋅ i and the result is x0 + x1 ⋅ i.
    /// @notice Will revert with InvalidProof() if
    ///   * the input is not a square,
    ///   * the hint is incorrect, or
    ///   * the input coefficients are not reduced.
    /// @param a0 The real part of the input.
    /// @param a1 The imaginary part of the input.
    /// @param hint A hint which of two possible signs to pick in the equation.
    /// @return x0 The real part of the square root.
    /// @return x1 The imaginary part of the square root.
    function sqrt_Fp2(uint256 a0, uint256 a1, bool hint) internal view returns (uint256 x0, uint256 x1) {
        // If this square root reverts there is no solution in Fp2.
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        // If this square root reverts there is no solution in Fp2.
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        // Check result to make sure we found a root.
        // Note: this also fails if a0 or a1 is not reduced.
        if (a0 != addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P)
        ||  a1 != mulmod(2, mulmod(x0, x1, P), P)) {
            revert ProofInvalid();
        }
    }

    /// Compress a G1 point.
    /// @notice Reverts with InvalidProof if the coordinates are not reduced
    /// or if the point is not on the curve.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param x The X coordinate in Fp.
    /// @param y The Y coordinate in Fp.
    /// @return c The compresed point (x with one signal bit).
    function compress_g1(uint256 x, uint256 y) internal view returns (uint256 c) {
        if (x >= P || y >= P) {
            // G1 point not in field.
            revert ProofInvalid();
        }
        if (x == 0 && y == 0) {
            // Point at infinity
            return 0;
        }

        // Note: sqrt_Fp reverts if there is no solution, i.e. the x coordinate is invalid.
        uint256 y_pos = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (y == y_pos) {
            return (x << 1) | 0;
        } else if (y == negate(y_pos)) {
            return (x << 1) | 1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G1 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param c The compresed point (x with one signal bit).
    /// @return x The X coordinate in Fp.
    /// @return y The Y coordinate in Fp.
    function decompress_g1(uint256 c) internal view returns (uint256 x, uint256 y) {
        // Note that X = 0 is not on the curve since 0³ + 3 = 3 is not a square.
        // so we can use it to represent the point at infinity.
        if (c == 0) {
            // Point at infinity as encoded in EIP196 and EIP197.
            return (0, 0);
        }
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        if (x >= P) {
            // G1 x coordinate not in field.
            revert ProofInvalid();
        }

        // Note: (x³ + 3) is irreducible in Fp, so it can not be zero and therefore
        //       y can not be zero.
        // Note: sqrt_Fp reverts if there is no solution, i.e. the point is not on the curve.
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
        }
    }

    /// Compress a G2 point.
    /// @notice Reverts with InvalidProof if the coefficients are not reduced
    /// or if the point is not on the curve.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param x0 The real part of the X coordinate.
    /// @param x1 The imaginary poart of the X coordinate.
    /// @param y0 The real part of the Y coordinate.
    /// @param y1 The imaginary part of the Y coordinate.
    /// @return c0 The first half of the compresed point (x0 with two signal bits).
    /// @return c1 The second half of the compressed point (x1 unmodified).
    function compress_g2(uint256 x0, uint256 x1, uint256 y0, uint256 y1)
    internal view returns (uint256 c0, uint256 c1) {
        if (x0 >= P || x1 >= P || y0 >= P || y1 >= P) {
            // G2 point not in field.
            revert ProofInvalid();
        }
        if ((x0 | x1 | y0 | y1) == 0) {
            // Point at infinity
            return (0, 0);
        }

        // Compute y^2
        // Note: shadowing variables and scoping to avoid stack-to-deep.
        uint256 y0_pos;
        uint256 y1_pos;
        {
            uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
            uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
            uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);
            y0_pos = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
            y1_pos = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));
        }

        // Determine hint bit
        // If this sqrt fails the x coordinate is not on the curve.
        bool hint;
        {
            uint256 d = sqrt_Fp(addmod(mulmod(y0_pos, y0_pos, P), mulmod(y1_pos, y1_pos, P), P));
            hint = !isSquare_Fp(mulmod(addmod(y0_pos, d, P), FRACTION_1_2_FP, P));
        }

        // Recover y
        (y0_pos, y1_pos) = sqrt_Fp2(y0_pos, y1_pos, hint);
        if (y0 == y0_pos && y1 == y1_pos) {
            c0 = (x0 << 2) | (hint ? 2  : 0) | 0;
            c1 = x1;
        } else if (y0 == negate(y0_pos) && y1 == negate(y1_pos)) {
            c0 = (x0 << 2) | (hint ? 2  : 0) | 1;
            c1 = x1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G2 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param c0 The first half of the compresed point (x0 with two signal bits).
    /// @param c1 The second half of the compressed point (x1 unmodified).
    /// @return x0 The real part of the X coordinate.
    /// @return x1 The imaginary poart of the X coordinate.
    /// @return y0 The real part of the Y coordinate.
    /// @return y1 The imaginary part of the Y coordinate.
    function decompress_g2(uint256 c0, uint256 c1)
    internal view returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1) {
        // Note that X = (0, 0) is not on the curve since 0³ + 3/(9 + i) is not a square.
        // so we can use it to represent the point at infinity.
        if (c0 == 0 && c1 == 0) {
            // Point at infinity as encoded in EIP197.
            return (0, 0, 0, 0);
        }
        bool negate_point = c0 & 1 == 1;
        bool hint = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;
        if (x0 >= P || x1 >= P) {
            // G2 x0 or x1 coefficient not in field.
            revert ProofInvalid();
        }

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));

        // Note: sqrt_Fp2 reverts if there is no solution, i.e. the point is not on the curve.
        // Note: (X³ + 3/(9 + i)) is irreducible in Fp2, so y can not be zero.
        //       But y0 or y1 may still independently be zero.
        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }

    /// Compute the public input linear combination.
    /// @notice Reverts with PublicInputNotInField if the input is not in the field.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @param publicCommitments public inputs generated from pedersen commitments.
    /// @param commitments The Pedersen commitments from the proof.
    /// @return x The X coordinate of the resulting G1 point.
    /// @return y The Y coordinate of the resulting G1 point.
    function publicInputMSM(
        uint256[64] calldata input,
        uint256[1] memory publicCommitments,
        uint256[2] memory commitments
    )
    internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We reduce commitments(if any) with constants as the first point argument to ECADD.
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            mstore(g, mload(commitments))
            mstore(add(g, 0x20), mload(add(commitments, 0x20)))
            success := and(success,  staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_0_X)
            mstore(add(g, 0x20), PUB_0_Y)
            s :=  calldataload(input)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_1_X)
            mstore(add(g, 0x20), PUB_1_Y)
            s :=  calldataload(add(input, 32))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_2_X)
            mstore(add(g, 0x20), PUB_2_Y)
            s :=  calldataload(add(input, 64))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_3_X)
            mstore(add(g, 0x20), PUB_3_Y)
            s :=  calldataload(add(input, 96))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_4_X)
            mstore(add(g, 0x20), PUB_4_Y)
            s :=  calldataload(add(input, 128))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_5_X)
            mstore(add(g, 0x20), PUB_5_Y)
            s :=  calldataload(add(input, 160))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_6_X)
            mstore(add(g, 0x20), PUB_6_Y)
            s :=  calldataload(add(input, 192))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_7_X)
            mstore(add(g, 0x20), PUB_7_Y)
            s :=  calldataload(add(input, 224))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_8_X)
            mstore(add(g, 0x20), PUB_8_Y)
            s :=  calldataload(add(input, 256))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_9_X)
            mstore(add(g, 0x20), PUB_9_Y)
            s :=  calldataload(add(input, 288))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_10_X)
            mstore(add(g, 0x20), PUB_10_Y)
            s :=  calldataload(add(input, 320))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_11_X)
            mstore(add(g, 0x20), PUB_11_Y)
            s :=  calldataload(add(input, 352))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_12_X)
            mstore(add(g, 0x20), PUB_12_Y)
            s :=  calldataload(add(input, 384))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_13_X)
            mstore(add(g, 0x20), PUB_13_Y)
            s :=  calldataload(add(input, 416))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_14_X)
            mstore(add(g, 0x20), PUB_14_Y)
            s :=  calldataload(add(input, 448))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_15_X)
            mstore(add(g, 0x20), PUB_15_Y)
            s :=  calldataload(add(input, 480))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_16_X)
            mstore(add(g, 0x20), PUB_16_Y)
            s :=  calldataload(add(input, 512))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_17_X)
            mstore(add(g, 0x20), PUB_17_Y)
            s :=  calldataload(add(input, 544))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_18_X)
            mstore(add(g, 0x20), PUB_18_Y)
            s :=  calldataload(add(input, 576))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_19_X)
            mstore(add(g, 0x20), PUB_19_Y)
            s :=  calldataload(add(input, 608))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_20_X)
            mstore(add(g, 0x20), PUB_20_Y)
            s :=  calldataload(add(input, 640))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_21_X)
            mstore(add(g, 0x20), PUB_21_Y)
            s :=  calldataload(add(input, 672))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_22_X)
            mstore(add(g, 0x20), PUB_22_Y)
            s :=  calldataload(add(input, 704))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_23_X)
            mstore(add(g, 0x20), PUB_23_Y)
            s :=  calldataload(add(input, 736))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_24_X)
            mstore(add(g, 0x20), PUB_24_Y)
            s :=  calldataload(add(input, 768))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_25_X)
            mstore(add(g, 0x20), PUB_25_Y)
            s :=  calldataload(add(input, 800))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_26_X)
            mstore(add(g, 0x20), PUB_26_Y)
            s :=  calldataload(add(input, 832))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_27_X)
            mstore(add(g, 0x20), PUB_27_Y)
            s :=  calldataload(add(input, 864))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_28_X)
            mstore(add(g, 0x20), PUB_28_Y)
            s :=  calldataload(add(input, 896))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_29_X)
            mstore(add(g, 0x20), PUB_29_Y)
            s :=  calldataload(add(input, 928))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_30_X)
            mstore(add(g, 0x20), PUB_30_Y)
            s :=  calldataload(add(input, 960))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_31_X)
            mstore(add(g, 0x20), PUB_31_Y)
            s :=  calldataload(add(input, 992))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_32_X)
            mstore(add(g, 0x20), PUB_32_Y)
            s :=  calldataload(add(input, 1024))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_33_X)
            mstore(add(g, 0x20), PUB_33_Y)
            s :=  calldataload(add(input, 1056))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_34_X)
            mstore(add(g, 0x20), PUB_34_Y)
            s :=  calldataload(add(input, 1088))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_35_X)
            mstore(add(g, 0x20), PUB_35_Y)
            s :=  calldataload(add(input, 1120))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_36_X)
            mstore(add(g, 0x20), PUB_36_Y)
            s :=  calldataload(add(input, 1152))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_37_X)
            mstore(add(g, 0x20), PUB_37_Y)
            s :=  calldataload(add(input, 1184))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_38_X)
            mstore(add(g, 0x20), PUB_38_Y)
            s :=  calldataload(add(input, 1216))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_39_X)
            mstore(add(g, 0x20), PUB_39_Y)
            s :=  calldataload(add(input, 1248))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_40_X)
            mstore(add(g, 0x20), PUB_40_Y)
            s :=  calldataload(add(input, 1280))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_41_X)
            mstore(add(g, 0x20), PUB_41_Y)
            s :=  calldataload(add(input, 1312))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_42_X)
            mstore(add(g, 0x20), PUB_42_Y)
            s :=  calldataload(add(input, 1344))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_43_X)
            mstore(add(g, 0x20), PUB_43_Y)
            s :=  calldataload(add(input, 1376))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_44_X)
            mstore(add(g, 0x20), PUB_44_Y)
            s :=  calldataload(add(input, 1408))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_45_X)
            mstore(add(g, 0x20), PUB_45_Y)
            s :=  calldataload(add(input, 1440))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_46_X)
            mstore(add(g, 0x20), PUB_46_Y)
            s :=  calldataload(add(input, 1472))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_47_X)
            mstore(add(g, 0x20), PUB_47_Y)
            s :=  calldataload(add(input, 1504))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_48_X)
            mstore(add(g, 0x20), PUB_48_Y)
            s :=  calldataload(add(input, 1536))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_49_X)
            mstore(add(g, 0x20), PUB_49_Y)
            s :=  calldataload(add(input, 1568))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_50_X)
            mstore(add(g, 0x20), PUB_50_Y)
            s :=  calldataload(add(input, 1600))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_51_X)
            mstore(add(g, 0x20), PUB_51_Y)
            s :=  calldataload(add(input, 1632))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_52_X)
            mstore(add(g, 0x20), PUB_52_Y)
            s :=  calldataload(add(input, 1664))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_53_X)
            mstore(add(g, 0x20), PUB_53_Y)
            s :=  calldataload(add(input, 1696))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_54_X)
            mstore(add(g, 0x20), PUB_54_Y)
            s :=  calldataload(add(input, 1728))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_55_X)
            mstore(add(g, 0x20), PUB_55_Y)
            s :=  calldataload(add(input, 1760))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_56_X)
            mstore(add(g, 0x20), PUB_56_Y)
            s :=  calldataload(add(input, 1792))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_57_X)
            mstore(add(g, 0x20), PUB_57_Y)
            s :=  calldataload(add(input, 1824))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_58_X)
            mstore(add(g, 0x20), PUB_58_Y)
            s :=  calldataload(add(input, 1856))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_59_X)
            mstore(add(g, 0x20), PUB_59_Y)
            s :=  calldataload(add(input, 1888))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_60_X)
            mstore(add(g, 0x20), PUB_60_Y)
            s :=  calldataload(add(input, 1920))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_61_X)
            mstore(add(g, 0x20), PUB_61_Y)
            s :=  calldataload(add(input, 1952))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_62_X)
            mstore(add(g, 0x20), PUB_62_Y)
            s :=  calldataload(add(input, 1984))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_63_X)
            mstore(add(g, 0x20), PUB_63_Y)
            s :=  calldataload(add(input, 2016))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_64_X)
            mstore(add(g, 0x20), PUB_64_Y)
            s := mload(publicCommitments)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))

            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Compress a proof.
    /// @notice Will revert with InvalidProof if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @param commitments Pedersen commitments from the proof.
    /// @param commitmentPok proof of knowledge for the Pedersen commitments.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    /// @return compressedCommitments compressed Pedersen commitments from the proof.
    /// @return compressedCommitmentPok compressed proof of knowledge for the Pedersen commitments.
    function compressProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok
    )
    public view returns (
        uint256[4] memory compressed,
        uint256[1] memory compressedCommitments,
        uint256 compressedCommitmentPok
    ) {
        compressed[0] = compress_g1(proof[0], proof[1]);
        (compressed[2], compressed[1]) = compress_g2(proof[3], proof[2], proof[5], proof[4]);
        compressed[3] = compress_g1(proof[6], proof[7]);
        compressedCommitments[0] = compress_g1(commitments[0], commitments[1]);
        compressedCommitmentPok = compress_g1(commitmentPok[0], commitmentPok[1]);
    }

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the points (A, B, C) in compressed format
    /// matching the output of compressProof.
    /// @param compressedCommitments compressed Pedersen commitments from the proof.
    /// @param compressedCommitmentPok compressed proof of knowledge for the Pedersen commitments.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[1] calldata compressedCommitments,
        uint256 compressedCommitmentPok,
        uint256[64] calldata input
    ) public view {
        uint256[1] memory publicCommitments;
        uint256[2] memory commitments;
        uint256[24] memory pairings;
        {
            (commitments[0], commitments[1]) = decompress_g1(compressedCommitments[0]);
            (uint256 Px, uint256 Py) = decompress_g1(compressedCommitmentPok);

            uint256[] memory publicAndCommitmentCommitted;

            publicCommitments[0] = uint256(
                sha256(
                    abi.encodePacked(
                        commitments[0],
                        commitments[1],
                        publicAndCommitmentCommitted
                    )
                )
            ) % R;
            // Commitments
            pairings[ 0] = commitments[0];
            pairings[ 1] = commitments[1];
            pairings[ 2] = PEDERSEN_GSIGMANEG_X_1;
            pairings[ 3] = PEDERSEN_GSIGMANEG_X_0;
            pairings[ 4] = PEDERSEN_GSIGMANEG_Y_1;
            pairings[ 5] = PEDERSEN_GSIGMANEG_Y_0;
            pairings[ 6] = Px;
            pairings[ 7] = Py;
            pairings[ 8] = PEDERSEN_G_X_1;
            pairings[ 9] = PEDERSEN_G_X_0;
            pairings[10] = PEDERSEN_G_Y_1;
            pairings[11] = PEDERSEN_G_Y_0;

            // Verify pedersen commitments
            bool success;
            assembly ("memory-safe") {
                let f := mload(0x40)

                success := staticcall(gas(), PRECOMPILE_VERIFY, pairings, 0x180, f, 0x20)
                success := and(success, mload(f))
            }
            if (!success) {
                revert CommitmentInvalid();
            }
        }

        {
            (uint256 Ax, uint256 Ay) = decompress_g1(compressedProof[0]);
            (uint256 Bx0, uint256 Bx1, uint256 By0, uint256 By1) = decompress_g2(compressedProof[2], compressedProof[1]);
            (uint256 Cx, uint256 Cy) = decompress_g1(compressedProof[3]);
            (uint256 Lx, uint256 Ly) = publicInputMSM(
                input,
                publicCommitments,
                commitments
            );

            // Verify the pairing
            // Note: The precompile expects the F2 coefficients in big-endian order.
            // Note: The pairing precompile rejects unreduced values, so we won't check that here.
            // e(A, B)
            pairings[ 0] = Ax;
            pairings[ 1] = Ay;
            pairings[ 2] = Bx1;
            pairings[ 3] = Bx0;
            pairings[ 4] = By1;
            pairings[ 5] = By0;
            // e(C, -δ)
            pairings[ 6] = Cx;
            pairings[ 7] = Cy;
            pairings[ 8] = DELTA_NEG_X_1;
            pairings[ 9] = DELTA_NEG_X_0;
            pairings[10] = DELTA_NEG_Y_1;
            pairings[11] = DELTA_NEG_Y_0;
            // e(α, -β)
            pairings[12] = ALPHA_X;
            pairings[13] = ALPHA_Y;
            pairings[14] = BETA_NEG_X_1;
            pairings[15] = BETA_NEG_X_0;
            pairings[16] = BETA_NEG_Y_1;
            pairings[17] = BETA_NEG_Y_0;
            // e(L_pub, -γ)
            pairings[18] = Lx;
            pairings[19] = Ly;
            pairings[20] = GAMMA_NEG_X_1;
            pairings[21] = GAMMA_NEG_X_0;
            pairings[22] = GAMMA_NEG_Y_1;
            pairings[23] = GAMMA_NEG_Y_0;

            // Check pairing equation.
            bool success;
            uint256[1] memory output;
            assembly ("memory-safe") {
                success := staticcall(gas(), PRECOMPILE_VERIFY, pairings, 0x300, output, 0x20)
            }
            if (!success || output[0] != 1) {
                // Either proof or verification key invalid.
                // We assume the contract is correctly generated, so the verification key is valid.
                revert ProofInvalid();
            }
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param commitments the Pedersen commitments from the proof.
    /// @param commitmentPok the proof of knowledge for the Pedersen commitments.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[64] calldata input
    ) public view {
        // HashToField
        uint256[1] memory publicCommitments;
        uint256[] memory publicAndCommitmentCommitted;

            publicCommitments[0] = uint256(
                sha256(
                    abi.encodePacked(
                        commitments[0],
                        commitments[1],
                        publicAndCommitmentCommitted
                    )
                )
            ) % R;

        // Verify pedersen commitments
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)

            calldatacopy(f, commitments, 0x40) // Copy Commitments
            mstore(add(f, 0x40), PEDERSEN_GSIGMANEG_X_1)
            mstore(add(f, 0x60), PEDERSEN_GSIGMANEG_X_0)
            mstore(add(f, 0x80), PEDERSEN_GSIGMANEG_Y_1)
            mstore(add(f, 0xa0), PEDERSEN_GSIGMANEG_Y_0)
            calldatacopy(add(f, 0xc0), commitmentPok, 0x40)
            mstore(add(f, 0x100), PEDERSEN_G_X_1)
            mstore(add(f, 0x120), PEDERSEN_G_X_0)
            mstore(add(f, 0x140), PEDERSEN_G_Y_1)
            mstore(add(f, 0x160), PEDERSEN_G_Y_0)

            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x180, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            revert CommitmentInvalid();
        }

        (uint256 x, uint256 y) = publicInputMSM(
            input,
            publicCommitments,
            commitments
        );

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
