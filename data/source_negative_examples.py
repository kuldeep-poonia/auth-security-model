import datetime
import json
import os
import sys
from typing import Any, Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data.clean_and_dedup import compute_code_hash


def build_negative_examples_from_fixed_pairs(
    positive_records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Generate verified negative examples from the fixed ('after') code units of CVE pairs."""
    negative_records = []
    seen_hashes = set()

    for pos in positive_records:
        fixed_code = pos.get("fixed_code", "").strip()
        if not fixed_code:
            continue

        h = compute_code_hash(fixed_code)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        neg_record = {
            "id": f"{pos['id']}-clean-fix",
            "source": pos["source"],
            "cwe_ids": [],
            "vuln_class": "none",
            "language": pos["language"],
            "code": fixed_code,
            "is_vulnerable": False,
            "explanation": "Verified fixed code unit with properly enforced authentication and authorization checks.",
            "provenance": {
                "derived_from": pos["id"],
                "repo_url": pos["provenance"]["repo_url"],
                "commit_hash": pos["provenance"]["commit_hash"],
                "type": "fixed_pair_negative",
            },
        }
        negative_records.append(neg_record)

    return negative_records


def build_curated_clean_auth_patterns() -> List[Dict[str, Any]]:
    """Curated standard clean auth/authz patterns across primary languages."""
    return [
        # Python - Clean Django Ownership & Permission
        {
            "id": "clean-py-django-01",
            "source": "curated_clean_patterns",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": "python",
            "code": """def update_user_profile(request, profile_id):
    profile = get_object_or_404(UserProfile, id=profile_id)
    if profile.user != request.user and not request.user.has_perm('profiles.change_userprofile'):
        raise PermissionDenied("You do not have permission to modify this profile.")
    form = UserProfileForm(request.POST, instance=profile)
    if form.is_valid():
        form.save()
        return JsonResponse({"status": "success"})
    return JsonResponse({"errors": form.errors}, status=400)""",
            "is_vulnerable": False,
            "explanation": "Validates explicit object ownership and administrative permissions before modifying profile.",
            "provenance": {"type": "framework_clean_pattern", "framework": "django"},
        },
        # JavaScript/Node - Clean JWT RBAC Guard
        {
            "id": "clean-js-express-01",
            "source": "curated_clean_patterns",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": "javascript",
            "code": """function requireRole(allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(401).json({ error: "Authentication required" });
        }
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: "Forbidden: insufficient permissions" });
        }
        next();
    };
}""",
            "is_vulnerable": False,
            "explanation": "Proper middleware verifying authenticated session and user role against allowed role list.",
            "provenance": {"type": "framework_clean_pattern", "framework": "express"},
        },
        # Go - Clean RBAC & Tenant Scoping
        {
            "id": "clean-go-rbac-01",
            "source": "curated_clean_patterns",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": "go",
            "code": """func GetTenantResource(ctx context.Context, tenantID, resourceID string, user User) (*Resource, error) {
    if user.TenantID != tenantID && !user.IsPlatformAdmin {
        return nil, ErrUnauthorizedTenantAccess
    }
    resource, err := db.FindResource(ctx, tenantID, resourceID)
    if err != nil {
        return nil, err
    }
    if resource.OwnerID != user.ID && !user.HasPermission("resources.read") {
        return nil, ErrForbidden
    }
    return resource, nil
}""",
            "is_vulnerable": False,
            "explanation": "Strict dual validation of tenant isolation and resource ownership permissions.",
            "provenance": {"type": "framework_clean_pattern", "framework": "go-standard"},
        },
        # Java - Clean Spring Security Method Security
        {
            "id": "clean-java-spring-01",
            "source": "curated_clean_patterns",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": "java",
            "code": """@PreAuthorize("hasRole('ADMIN') or #account.ownerId == authentication.principal.id")
@Transactional
public AccountDTO updateAccountSettings(@P("account") AccountSettingsUpdateRequest request) {
    Account account = accountRepository.findById(request.getAccountId())
        .orElseThrow(() -> new ResourceNotFoundException("Account not found"));
    account.setNotificationPreferences(request.getPreferences());
    return accountMapper.toDTO(accountRepository.save(account));
}""",
            "is_vulnerable": False,
            "explanation": "Declarative Spring PreAuthorize guard enforcing admin role or authenticated ownership.",
            "provenance": {"type": "framework_clean_pattern", "framework": "spring-security"},
        },
        # PHP - Clean Laravel Policy Check
        {
            "id": "clean-php-laravel-01",
            "source": "curated_clean_patterns",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": "php",
            "code": """public function update(Request $request, Invoice $invoice)
{
    $this->authorize('update', $invoice);
    $validated = $request->validate([
        'amount' => 'required|numeric|min:0',
        'status' => 'required|string|in:draft,sent,paid',
    ]);
    $invoice->update($validated);
    return response()->json($invoice);
}""",
            "is_vulnerable": False,
            "explanation": "Explicit Laravel policy authorization check ensuring caller has update permissions on invoice.",
            "provenance": {"type": "framework_clean_pattern", "framework": "laravel"},
        },
        # TypeScript - Clean NestJS Policy Guard
        {
            "id": "clean-ts-nest-01",
            "source": "curated_clean_patterns",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": "typescript",
            "code": """@Injectable()
export class PoliciesGuard implements CanActivate {
  constructor(private reflector: Reflector, private abilityFactory: CaslAbilityFactory) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const rules = this.reflector.get<PolicyHandler[]>(CHECK_POLICIES_KEY, context.getHandler()) || [];
    const { user } = context.switchToHttp().getRequest();
    if (!user) return false;
    const ability = this.abilityFactory.createForUser(user);
    return rules.every(handler => handler.handle(ability));
  }
}""",
            "is_vulnerable": False,
            "explanation": "NestJS CanActivate guard evaluating fine-grained CASL abilities for authenticated principal.",
            "provenance": {"type": "framework_clean_pattern", "framework": "nestjs"},
        },
    ]


def extract_clean_code_from_raw_diff(raw_diff: str) -> str:
    """Extract actual clean code snippet from diff headers if present."""
    lines = raw_diff.splitlines()
    code_lines = []
    in_code = False
    for line in lines:
        if line.startswith("@@"):
            in_code = True
            continue
        if in_code:
            code_lines.append(line)
        elif not (line.startswith("diff --git") or line.startswith("---") or line.startswith("+++")):
            code_lines.append(line)
    return "\n".join(code_lines).strip()


def load_real_framework_negatives(
    framework_negatives_path: str = "data/raw/framework_negatives/real_framework_negatives.json",
) -> List[Dict[str, Any]]:
    """Load real production authorization code modules extracted from framework repositories."""
    if not os.path.exists(framework_negatives_path):
        return []

    with open(framework_negatives_path, "r", encoding="utf-8") as f:
        raw_items = json.load(f)

    clean_negatives = []
    seen_hashes = set()

    for item in raw_items:
        clean_code = extract_clean_code_from_raw_diff(item.get("raw_diff", ""))
        if not clean_code or len(clean_code) < 30:
            continue

        h = compute_code_hash(clean_code)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        clean_negatives.append({
            "id": item["id"],
            "source": "real_framework_negative",
            "cwe_ids": [],
            "vuln_class": "none",
            "language": item["language"],
            "code": clean_code,
            "is_vulnerable": False,
            "explanation": item.get("commit_message", "Production-grade authorization module from framework repository."),
            "provenance": item.get("provenance", {}),
        })

    return clean_negatives


def generate_negative_dataset(
    positive_pairs_path: str = "data/cleaned_positive_pairs.json",
    framework_negatives_path: str = "data/raw/framework_negatives/real_framework_negatives.json",
    output_path: str = "data/cleaned_negative_examples.json",
) -> List[Dict[str, Any]]:
    """Assemble complete negative examples dataset from fixed code units, real framework code, and clean patterns."""
    if not os.path.exists(positive_pairs_path):
        print(f"[WARN] Positive pairs not found at {positive_pairs_path}")
        return []

    with open(positive_pairs_path, "r", encoding="utf-8") as f:
        positive_records = json.load(f)

    fixed_negatives = build_negative_examples_from_fixed_pairs(positive_records)
    framework_negatives = load_real_framework_negatives(framework_negatives_path)
    curated_negatives = build_curated_clean_auth_patterns()

    all_candidates = fixed_negatives + framework_negatives + curated_negatives
    all_negatives = []
    seen_hashes = set()

    for item in all_candidates:
        h = compute_code_hash(item["code"])
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        all_negatives.append(item)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_negatives, f, indent=2)

    print(f"[OK] Generated {len(all_negatives)} unique negative examples ({len(fixed_negatives)} from fixed pairs, {len(framework_negatives)} from real frameworks, {len(curated_negatives)} curated patterns).")
    return all_negatives


if __name__ == "__main__":
    generate_negative_dataset()
