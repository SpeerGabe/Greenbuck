// service that handles the mitigation schemes and tracks which one is active
import 'mitigations/mitigation_scheme.dart';
import 'mitigations/constant_mitigation.dart';
import 'mitigations/jitter_mitigation.dart';
import 'mitigations/none_mitigation.dart';
import 'mitigations/padding_mitigation.dart';

class MitigationService {
  final Map<String, MitigationScheme> availableSchemes = {
    'constant': ConstantMitigation(),
    'jitter': JitterMitigation(),
    'none': NoMitigation(),
    'padding': PaddingMitigation(),
  };

  String activeSchemeName = "none";

  MitigationScheme get activeScheme => availableSchemes[activeSchemeName]!;

  void setActiveScheme(String schemeName) {
    if(!availableSchemes.containsKey(schemeName)) {
      throw ArgumentError("Unknown mitigation: $schemeName");
    }

    activeSchemeName = schemeName;


  }
}