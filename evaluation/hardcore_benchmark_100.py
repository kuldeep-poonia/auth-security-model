"""Hardcore 60-Case Adversarial Benchmark Suite for Auth & Authorization LLMs.

Spans 6 major programming languages and 12 modern backend frameworks:
- Python (FastAPI, Flask, Django, Strawberry GraphQL, Async SQLAlchemy)
- Go (Gin, Chi, Fiber, GORM, net/http)
- TypeScript / JavaScript (Next.js 14 Server Actions, Express, NestJS, Fastify, Prisma)
- Java (Spring Boot, Spring Security SpEL, JPA / Hibernate, Quarkus)
- C# / .NET (ASP.NET Core, Minimal APIs, Entity Framework Core)
- PHP (Laravel Eloquent, Symfony, Slim)

Covers 6 distinct vulnerability and security mechanics:
1. Multi-Tenant, Nested Resource & Bulk Batch IDOR
2. Authentication Bypass (Algorithm Confusion, Header Trust, Token Invalidation)
3. Cryptographic Side-Channels & Timing Leakage
4. Role Hierarchy, Bitmask & Relational Logic Inversions
5. Framework-Specific Object-Level Permission Omissions
6. Complex Sound Defensive Baselines (Hard Negatives - Zero Tolerance for False Positives)
"""

from typing import Any, Dict, List

HARDCORE_BENCHMARK_CASES: List[Dict[str, Any]] = [
    # ==========================================================================
    # 1. PYTHON (10 Cases)
    # ==========================================================================
    {
        "id": "py-hardcore-01-graphql-idor",
        "title": "GraphQL Nested Audit Log IDOR (Python / Strawberry + SQLAlchemy)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Parent resolver validates tenant access, but child field resolver fetches private AuditLog records directly by log_id without asserting log.tenant_id == current_user.tenant_id.",
        "code": """@strawberry.type
class Query:
    @strawberry.field
    async def organization(self, info: Info, org_id: UUID) -> Optional[OrganizationType]:
        user = info.context.current_user
        db: AsyncSession = info.context.db
        membership = await db.scalar(select(OrgMember).where(OrgMember.org_id == org_id, OrgMember.user_id == user.id))
        if not membership:
            raise PermissionError("Access denied to organization")
        return await db.scalar(select(Organization).where(Organization.id == org_id))

    @strawberry.field
    async def audit_log_entry(self, info: Info, log_id: UUID) -> Optional[AuditLogType]:
        user = info.context.current_user
        if not user.is_authenticated:
            raise PermissionError("Authentication required")
        db: AsyncSession = info.context.db
        # Flaw: Un-scoped audit log lookup by log_id allows cross-tenant log exfiltration
        entry = await db.scalar(select(AuditLog).where(AuditLog.id == log_id))
        return entry"""
    },
    {
        "id": "py-hardcore-02-bulk-update-idor",
        "title": "Bulk Batch Task Archive IDOR (Python / FastAPI + Async SQLAlchemy)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Verifies caller belongs to workspace, but bulk updates tasks using `Task.id.in_(payload.task_ids)` without scoping `Task.workspace_id == ws_id`.",
        "code": """@router.post("/workspaces/{ws_id}/tasks/bulk-archive")
async def bulk_archive_workspace_tasks(
    ws_id: UUID,
    payload: BulkTaskPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    ws_member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == ws_id,
            WorkspaceMember.user_id == current_user.id
        )
    )
    if not ws_member:
        raise HTTPException(status_code=403, detail="Not a member of this workspace")

    # Flaw: Omits workspace_id filter in bulk update, allowing archiving tasks in other workspaces
    stmt = (
        update(Task)
        .where(Task.id.in_(payload.task_ids))
        .values(is_archived=True, archived_at=datetime.utcnow())
    )
    await db.execute(stmt)
    await db.commit()
    return {"status": "success", "count": len(payload.task_ids)}"""
    },
    {
        "id": "py-hardcore-03-hmac-timing-len",
        "title": "Webhook HMAC Length Check Timing Attack (Python / Flask)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Guards constant-time comparison with a pre-check `len(sig) != len(expected_mac)`, leaking expected MAC length and creating side-channel timing discrepancy.",
        "code": """def verify_incoming_webhook(payload_bytes: bytes, signature_hdr: str, secret: str) -> bool:
    if not signature_hdr or not secret:
        return False
    expected_mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    # Flaw: Fast-fail length check leaks length and bypasses constant-time guarantee
    if len(signature_hdr) != len(expected_mac):
        return False
    return hmac.compare_digest(signature_hdr, expected_mac)"""
    },
    {
        "id": "py-hardcore-04-enum-hierarchy-flaw",
        "title": "IntEnum Privilege Escalation on Inactive State (Python / Django Decorator)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "Compares `request.user.role >= required_role` where `UserRole.SUSPENDED = 3` has higher numerical value than `AUDITOR = 1` or `ADMIN = 2`.",
        "code": """class UserRole(IntEnum):
    GUEST = 0
    AUDITOR = 1
    ADMIN = 2
    SUSPENDED = 3  # Inactive account state

def require_minimum_clearance(required_role: UserRole):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseForbidden("Authentication required")
            # Flaw: SUSPENDED (3) accounts satisfy >= check for AUDITOR (1) or ADMIN (2)
            if request.user.role >= required_role:
                return view_func(request, *args, **kwargs)
            return HttpResponseForbidden("Insufficient permission level")
        return _wrapped_view
    return decorator"""
    },
    {
        "id": "py-hardcore-05-drf-omit-obj-perms",
        "title": "DRF get_object() Object-Level Permission Omission (Python / DRF)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Overrides `get_object()` with `get_object_or_404` but omits `self.check_object_permissions(self.request, obj)`, bypassing `IsOwnerOrAuditor` object rule.",
        "code": """class FinancialReportViewSet(viewsets.ModelViewSet):
    queryset = FinancialReport.objects.all()
    serializer_class = FinancialReportSerializer
    permission_classes = [permissions.IsAuthenticated, IsReportOwnerOrAuditor]

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        # Flaw: Returns obj directly without invoking self.check_object_permissions(self.request, obj)
        obj = get_object_or_404(queryset, **filter_kwargs)
        return obj"""
    },
    {
        "id": "py-hardcore-06-pessimistic-lock-transfer",
        "title": "Sound Pessimistic Row-Locked Asset Transfer (Python / Django)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses transaction.atomic(), select_for_update(), verifies sender ownership, balance sufficiency, and idempotency key.",
        "code": """@api_view(['POST'])
@permission_classes([IsAuthenticated])
def execute_internal_asset_transfer(request):
    source_wallet_id = request.data.get('source_wallet_id')
    dest_wallet_id = request.data.get('dest_wallet_id')
    transfer_amount = Decimal(str(request.data.get('amount', '0')))
    idempotency_key = request.headers.get('X-Idempotency-Key')

    if transfer_amount <= 0 or not idempotency_key:
        return Response({'error': 'Invalid transfer parameters'}, status=400)

    with transaction.atomic():
        if TransferLog.objects.filter(idempotency_key=idempotency_key, user=request.user).exists():
            return Response({'status': 'duplicate_request_ignored'}, status=200)

        source = Wallet.objects.select_for_update().filter(id=source_wallet_id, owner=request.user).first()
        if not source or source.balance < transfer_amount:
            return Response({'error': 'Insufficient funds or wallet not owned'}, status=403)

        dest = Wallet.objects.select_for_update().filter(id=dest_wallet_id).first()
        if not dest:
            return Response({'error': 'Destination wallet not found'}, status=404)

        source.balance -= transfer_amount
        dest.balance += transfer_amount
        source.save()
        dest.save()
        TransferLog.objects.create(idempotency_key=idempotency_key, user=request.user, amount=transfer_amount)

    return Response({'status': 'transfer_completed'}, status=200)"""
    },
    {
        "id": "py-hardcore-07-secure-reset-token",
        "title": "Sound Constant-Time Single-Use Password Reset (Python / Flask)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Validates single-use token in constant time, checks expiry timestamp in UTC, invalidates token atomically with lock.",
        "code": """@app.route('/api/auth/consume-reset-token', methods=['POST'])
def consume_password_reset():
    data = request.get_json() or {}
    token_str = data.get('token')
    new_password = data.get('new_password')
    if not token_str or not new_password or len(new_password) < 10:
        return jsonify({'error': 'Invalid request parameters'}), 400

    token_hash = hashlib.sha256(token_str.encode('utf-8')).hexdigest()
    with db.session.begin():
        record = PasswordResetToken.query.filter_by(token_hash=token_hash).with_for_update().first()
        if not record or record.is_consumed or datetime.now(timezone.utc) > record.expires_at:
            return jsonify({'error': 'Invalid, expired, or already consumed token'}), 400

        user = User.query.filter_by(id=record.user_id).first()
        user.set_password(new_password)
        record.is_consumed = True
        record.consumed_at = datetime.now(timezone.utc)

    return jsonify({'status': 'password_successfully_updated'}), 200"""
    },
    {
        "id": "py-hardcore-08-fastapi-composite-scope",
        "title": "Sound Composite Scoped Document Retrieval (Python / FastAPI)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Strictly scopes document query with composite condition `Document.id == doc_id, Document.owner_id == current_user.id`.",
        "code": """@router.get('/documents/{doc_id}')
async def get_user_document(
    doc_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Document).where(
        Document.id == doc_id,
        Document.owner_id == current_user.id
    )
    doc = await db.scalar(stmt)
    if not doc:
        raise HTTPException(status_code=404, detail='Document not found or unauthorized')
    return doc"""
    },
    {
        "id": "py-hardcore-09-header-spoof-admin",
        "title": "Direct Header Admin Bypass (Python / FastAPI)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Grants administrator permissions directly if `X-Internal-Admin` request header is 'true' without cryptographic HMAC or mTLS gateway assertion.",
        "code": """def is_authenticated_admin(request: Request) -> bool:
    # Flaw: Direct trust of client-controllable header without secret verification
    internal_header = request.headers.get("X-Internal-Admin")
    if internal_header == "true" or internal_header == "1":
        return True
    return False"""
    },
    {
        "id": "py-hardcore-10-sound-hmac-gateway",
        "title": "Sound Gateway Header Verification with HMAC (Python / Flask)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Verifies gateway secret signature in constant time before granting internal proxy user identity.",
        "code": """def extract_gateway_caller(request: Request, gateway_secret: str) -> Optional[UserIdentity]:
    user_id = request.headers.get("X-Gateway-User-Id")
    sig = request.headers.get("X-Gateway-Signature")
    if not user_id or not sig:
        return None
    expected_sig = hmac.new(gateway_secret.encode("utf-8"), user_id.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.encode("utf-8"), expected_sig.encode("utf-8")):
        return None
    return UserIdentity(user_id=user_id, is_authenticated=True)"""
    },

    # ==========================================================================
    # 2. GO (10 Cases)
    # ==========================================================================
    {
        "id": "go-hardcore-01-jwt-alg-none",
        "title": "JWT Signing Algorithm 'none' Bypass (Go / Chi + jwt-go)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Token verification callback accepts jwt.SigningMethodNone, allowing attackers to forge arbitrary claims with an empty signature.",
        "code": """func JWTAuthMiddleware(jwtKey []byte) func(http.Handler) http.Handler {
\treturn func(next http.Handler) http.Handler {
\t\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
\t\t\tauthHeader := r.Header.Get("Authorization")
\t\t\tif !strings.HasPrefix(authHeader, "Bearer ") {
\t\t\t\thttp.Error(w, "Missing auth token", http.StatusUnauthorized)
\t\t\t\treturn
\t\t\t}
\t\t\ttokenString := strings.TrimPrefix(authHeader, "Bearer ")
\t\t\ttoken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
\t\t\t\t// Flaw: Accepts 'none' signing method from unverified client header
\t\t\t\tif t.Method.Alg() == "none" {
\t\t\t\t\treturn jwt.UnsafeAllowNoneSignatureType, nil
\t\t\t\t}
\t\t\t\treturn jwtKey, nil
\t\t\t})
\t\t\tif err != nil || !token.Valid {
\t\t\t\thttp.Error(w, "Invalid token", http.StatusUnauthorized)
\t\t\t\treturn
\t\t\t}
\t\t\tnext.ServeHTTP(w, r)
\t\t})
\t}
}"""
    },
    {
        "id": "go-hardcore-02-gin-zero-bitmask",
        "title": "Zero-Bitmask Default Route Authorization Bypass (Go / Gin)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "Evaluates `user.Permissions & requiredMask == requiredMask`. When requiredMask is 0, unauthenticated users satisfy condition.",
        "code": """func RequirePermission(requiredMask uint64) gin.HandlerFunc {
\treturn func(c *gin.Context) {
\t\tuserObj, exists := c.Get("current_user")
\t\tuser, ok := userObj.(*UserModel)
\t\tif exists && ok && (user.Permissions & requiredMask == requiredMask) {
\t\t\tc.Next()
\t\t\treturn
\t\t}
\t\t// Flaw: Allows unauthenticated access when requiredMask == 0
\t\tif requiredMask == 0 {
\t\t\tc.Next()
\t\t\treturn
\t\t}
\t\tc.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient bitmask privileges"})
\t}
}"""
    },
    {
        "id": "go-hardcore-03-gorm-unscoped-delete",
        "title": "Unscoped Direct Record Deletion IDOR (Go / Fiber + GORM)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Deletes target record by URL parameter ID without asserting record.OwnerID == session.UserID.",
        "code": """func DeleteInvoiceHandler(db *gorm.DB) fiber.Handler {
\treturn func(c *fiber.Ctx) error {
\t\tinvoiceID := c.Params("id")
\t\t// Flaw: Deletes record matching ID without filtering by session user's tenant/owner ID
\t\tresult := db.Delete(&models.Invoice{}, "id = ?", invoiceID)
\t\tif result.Error != nil {
\t\t\treturn c.Status(fiber.StatusInternalServerError).JSON(fiber.H{"error": result.Error.Error()})
\t\t}
\t\tif result.RowsAffected == 0 {
\t\t\treturn c.Status(fiber.StatusNotFound).JSON(fiber.H{"error": "Invoice not found"})
\t\t}
\t\treturn c.SendStatus(fiber.StatusNoContent)
\t}
}"""
    },
    {
        "id": "go-hardcore-04-sound-gorm-scoped-delete",
        "title": "Sound Scoped Record Deletion (Go / Fiber + GORM)",
        "language": "go",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Strictly scopes GORM deletion with composite clause `id = ? AND owner_id = ?`.",
        "code": """func DeleteInvoiceSecureHandler(db *gorm.DB) fiber.Handler {
\treturn func(c *fiber.Ctx) error {
\t\tuserID, ok := c.Locals("user_id").(string)
\t\tif !ok || userID == "" {
\t\t\treturn c.Status(fiber.StatusUnauthorized).JSON(fiber.H{"error": "Unauthorized"})
\t\t}
\t\tinvoiceID := c.Params("id")
\t\tresult := db.Delete(&models.Invoice{}, "id = ? AND owner_id = ?", invoiceID, userID)
\t\tif result.Error != nil {
\t\t\treturn c.Status(fiber.StatusInternalServerError).JSON(fiber.H{"error": result.Error.Error()})
\t\t}
\t\tif result.RowsAffected == 0 {
\t\t\treturn c.Status(fiber.StatusNotFound).JSON(fiber.H{"error": "Invoice not found or unauthorized"})
\t\t}
\t\treturn c.SendStatus(fiber.StatusNoContent)
\t}
}"""
    },
    {
        "id": "go-hardcore-05-sound-crypto-subtle-compare",
        "title": "Sound Constant-Time HMAC Signature Verification (Go / net/http)",
        "language": "go",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `subtle.ConstantTimeCompare` across computed and received HMAC byte slices.",
        "code": """func VerifyWebhookSignature(payload []byte, receivedSigHex string, secretKey []byte) bool {
\tmac := hmac.New(sha256.New, secretKey)
\tmac.Write(payload)
\texpectedMAC := mac.Sum(nil)
\treceivedMAC, err := hex.DecodeString(receivedSigHex)
\tif err != nil {
\t\treturn false
\t}
\treturn subtle.ConstantTimeCompare(expectedMAC, receivedMAC) == 1
}"""
    },
    {
        "id": "go-hardcore-06-inverted-role-precedence",
        "title": "Inverted Role Clearance Evaluation (Go / Standard Library)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "Relational operator `<= LevelAuditor` inverts role check, granting privileges to GUEST (0) while rejecting ADMIN (3).",
        "code": """func HasAuditorClearance(u *User) bool {
\tif u == nil || !u.IsActive {
\t\treturn false
\t}
\t// Flaw: Relational check inverted (<= instead of >=), allowing unprivileged accounts
\tif u.ClearanceLevel <= LevelAuditor {
\t\treturn true
\t}
\treturn false
}"""
    },
    {
        "id": "go-hardcore-07-sound-role-whitelist",
        "title": "Sound Role Hierarchy Assertion (Go / Standard Library)",
        "language": "go",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Explicitly checks active status and validates `u.ClearanceLevel >= LevelAuditor`.",
        "code": """func HasAuditorClearanceSecure(u *User) bool {
\tif u == nil || !u.IsActive || u.IsSuspended {
\t\treturn false
\t}
\treturn u.ClearanceLevel >= LevelAuditor
}"""
    },
    {
        "id": "go-hardcore-08-missing-authz-admin-route",
        "title": "Missing Authorization on Destructive Reset Endpoint (Go / Gin)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Privileged database purge route exposed without applying authentication or role middleware.",
        "code": """func RegisterAdminRoutes(r *gin.Engine, db *gorm.DB) {
\t// Flaw: Missing authentication or admin authorization middleware on destructive handler
\tr.POST("/api/admin/purge-cache", func(c *gin.Context) {
\t\tif err := db.Exec("TRUNCATE TABLE cache_entries").Error; err != nil {
\t\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
\t\t\treturn
\t\t}
\t\tc.JSON(http.StatusOK, gin.H{"status": "purged"})
\t})
}"""
    },
    {
        "id": "go-hardcore-09-sound-admin-guard",
        "title": "Sound Protected Administrative Route (Go / Gin)",
        "language": "go",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Enforces strict JWT auth middleware and `RequireRole(RoleSuperAdmin)`.",
        "code": """func RegisterAdminRoutesSecure(r *gin.Engine, db *gorm.DB, authMid, adminMid gin.HandlerFunc) {
\tadminGroup := r.Group("/api/admin", authMid, adminMid)
\tadminGroup.POST("/purge-cache", func(c *gin.Context) {
\t\tif err := db.Exec("TRUNCATE TABLE cache_entries").Error; err != nil {
\t\t\tc.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
\t\t\treturn
\t\t}
\t\tc.JSON(http.StatusOK, gin.H{"status": "purged"})
\t})
}"""
    },
    {
        "id": "go-hardcore-10-chi-subresource-idor",
        "title": "Chi Sub-Resource Lookup Missing Parent Scoping (Go / Chi + GORM)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Route accepts orgID and documentID, checks org membership, but queries Document with only `id = ?` omitting `org_id = ?`.",
        "code": """func GetOrgDocumentHandler(db *gorm.DB) http.HandlerFunc {
\treturn func(w http.ResponseWriter, r *http.Request) {
\t\torgID := chi.URLParam(r, "orgID")
\t\tdocID := chi.URLParam(r, "docID")
\t\tuser := r.Context().Value("user").(*User)

\t\tvar member OrgMember
\t\tif err := db.Where("org_id = ? AND user_id = ?", orgID, user.ID).First(&member).Error; err != nil {
\t\t\thttp.Error(w, "Forbidden", http.StatusForbidden)
\t\t\treturn
\t\t}

\t\tvar doc Document
\t\t// Flaw: Missing org_id condition allows fetching document belonging to any other org
\t\tif err := db.Where("id = ?", docID).First(&doc).Error; err != nil {
\t\t\thttp.Error(w, "Document not found", http.StatusNotFound)
\t\t\treturn
\t\t}
\t\tjson.NewEncoder(w).Encode(doc)
\t}
}"""
    },

    # ==========================================================================
    # 3. TYPESCRIPT / JAVASCRIPT (10 Cases)
    # ==========================================================================
    {
        "id": "ts-hardcore-01-server-action-idor",
        "title": "Next.js 14 Server Action Missing Role Verification (TypeScript / Next.js)",
        "language": "typescript",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Server action verifies authentication session, but fails to check whether caller has Admin role in target team before deleting members.",
        "code": """"use server";

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function removeTeamMember(targetUserId: string, teamId: string) {
  const session = await auth();
  if (!session || !session.user) {
    throw new Error("Authentication required");
  }

  // Flaw: Does not verify caller is team administrator or workspace owner
  await prisma.teamMembership.delete({
    where: {
      teamId_userId: {
        teamId: teamId,
        userId: targetUserId,
      },
    },
  });

  return { success: true };
}"""
    },
    {
        "id": "ts-hardcore-02-sound-server-action-rbac",
        "title": "Sound Next.js Server Action with RBAC Verification (TypeScript / Next.js)",
        "language": "typescript",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Verifies caller has ADMIN or OWNER role in target team before executing deletion.",
        "code": """"use server";

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function removeTeamMemberSecure(targetUserId: string, teamId: string) {
  const session = await auth();
  if (!session || !session.user) {
    throw new Error("Authentication required");
  }

  const callerMembership = await prisma.teamMembership.findUnique({
    where: {
      teamId_userId: {
        teamId: teamId,
        userId: session.user.id,
      },
    },
  });

  if (!callerMembership || !["ADMIN", "OWNER"].includes(callerMembership.role)) {
    throw new Error("Forbidden: Insufficient team privileges");
  }

  await prisma.teamMembership.delete({
    where: {
      teamId_userId: {
        teamId: teamId,
        userId: targetUserId,
      },
    },
  });

  return { success: true };
}"""
    },
    {
        "id": "ts-hardcore-03-webhook-string-timing",
        "title": "Webhook Signature String Equality Timing Leak (TypeScript / Express)",
        "language": "typescript",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Calculates HMAC signature but compares with client header using !== operator instead of crypto.timingSafeEqual.",
        "code": """import crypto from "crypto";
import { Request, Response } from "express";

export function verifyStripeWebhook(req: Request, res: Response, next: Function) {
  const signature = req.headers["stripe-signature"] as string;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;
  if (!signature) {
    return res.status(401).json({ error: "Missing signature header" });
  }

  const computedHash = crypto
    .createHmac("sha256", webhookSecret)
    .update(req.body, "utf8")
    .digest("hex");

  // Flaw: Non-constant time string equality comparison leaks timing discrepancy
  if (computedHash !== signature) {
    return res.status(401).json({ error: "Invalid signature" });
  }
  return next();
}"""
    },
    {
        "id": "ts-hardcore-04-sound-webhook-timing-safe",
        "title": "Sound Webhook Signature Verification with Buffer TimingSafeEqual (TypeScript / Express)",
        "language": "typescript",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `crypto.timingSafeEqual` over fixed-length Buffer representations.",
        "code": """import crypto from "crypto";
import { Request, Response } from "express";

export function verifyStripeWebhookSecure(req: Request, res: Response, next: Function) {
  const signature = req.headers["stripe-signature"] as string;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;
  if (!signature) {
    return res.status(401).json({ error: "Missing signature header" });
  }

  const computedHash = crypto
    .createHmac("sha256", webhookSecret)
    .update(req.body, "utf8")
    .digest("hex");

  const sigBuf = Buffer.from(signature, "hex");
  const compBuf = Buffer.from(computedHash, "hex");

  if (sigBuf.length !== compBuf.length || !crypto.timingSafeEqual(sigBuf, compBuf)) {
    return res.status(401).json({ error: "Invalid signature" });
  }
  return next();
}"""
    },
    {
        "id": "js-hardcore-05-oauth2-pkce-exchange",
        "title": "Sound OAuth2 PKCE Cryptographic Code Exchange (JavaScript / Express)",
        "language": "javascript",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Verifies PKCE code_verifier SHA-256 base64url encoding matches code_challenge, validates client_id and redirect_uri binding.",
        "code": """app.post('/oauth/v2/token', async (req, res) => {
  const { grant_type, code, client_id, redirect_uri, code_verifier } = req.body;
  if (grant_type !== 'authorization_code' || !code || !code_verifier) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const authCode = await db.AuthCode.findOne({ where: { code } });
  if (!authCode || authCode.isUsed || new Date() > authCode.expiresAt) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  const calculatedChallenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url');

  if (!crypto.timingSafeEqual(Buffer.from(calculatedChallenge), Buffer.from(authCode.codeChallenge))) {
    return res.status(400).json({ error: 'invalid_grant_verifier' });
  }

  await authCode.update({ isUsed: true });
  const token = generateAccessToken(authCode.userId, authCode.scope);
  return res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
});"""
    },
    {
        "id": "js-hardcore-06-express-nested-idor",
        "title": "Express + Sequelize Unscoped Nested Item Lookup (JavaScript / Express)",
        "language": "javascript",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Verifies workspace membership, but retrieves item with `findByPk(id)` without asserting `item.workspaceId === wsId`.",
        "code": """app.get('/api/workspaces/:wsId/documents/:id', authenticateToken, async (req, res) => {
  try {
    const { wsId, id } = req.params;
    const member = await db.WorkspaceMember.findOne({
      where: { workspaceId: wsId, userId: req.user.id }
    });
    if (!member) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    // Flaw: Direct lookup by ID omitting workspaceId constraint
    const doc = await db.Document.findByPk(id);
    if (!doc) {
      return res.status(404).json({ error: 'Not found' });
    }
    return res.json(doc);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});"""
    },
    {
        "id": "js-hardcore-07-sound-express-scoped-lookup",
        "title": "Sound Scoped Nested Lookup (JavaScript / Express)",
        "language": "javascript",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses composite query `where: { id: id, workspaceId: wsId }`.",
        "code": """app.get('/api/workspaces/:wsId/documents/:id', authenticateToken, async (req, res) => {
  try {
    const { wsId, id } = req.params;
    const member = await db.WorkspaceMember.findOne({
      where: { workspaceId: wsId, userId: req.user.id }
    });
    if (!member) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const doc = await db.Document.findOne({
      where: { id: id, workspaceId: wsId }
    });
    if (!doc) {
      return res.status(404).json({ error: 'Not found or unauthorized' });
    }
    return res.json(doc);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});"""
    },
    {
        "id": "ts-hardcore-08-nestjs-missing-guard",
        "title": "NestJS Administrative Controller Method Missing Guard (TypeScript / NestJS)",
        "language": "typescript",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Controller class has JwtAuthGuard, but sensitive `purgeTenantData()` method omits `@Roles(Role.ADMIN)` guard.",
        "code": """@Controller('admin/tenants')
@UseGuards(JwtAuthGuard)
export class TenantAdminController {
  constructor(private tenantService: TenantService) {}

  // Flaw: Omits RolesGuard / @Roles(Role.ADMIN), allowing standard authenticated users to invoke purge
  @Delete(':id/purge')
  async purgeTenant(@Param('id') tenantId: string) {
    await this.tenantService.purgeAllTenantRecords(tenantId);
    return { status: 'tenant_purged' };
  }
}"""
    },
    {
        "id": "ts-hardcore-09-sound-nestjs-role-guard",
        "title": "Sound NestJS Protected Admin Endpoint (TypeScript / NestJS)",
        "language": "typescript",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Applies `@UseGuards(JwtAuthGuard, RolesGuard)` and `@Roles(Role.SUPERADMIN)`.",
        "code": """@Controller('admin/tenants')
@UseGuards(JwtAuthGuard, RolesGuard)
export class TenantAdminSecureController {
  constructor(private tenantService: TenantService) {}

  @Roles(Role.SUPERADMIN)
  @Delete(':id/purge')
  async purgeTenant(@Param('id') tenantId: string) {
    await this.tenantService.purgeAllTenantRecords(tenantId);
    return { status: 'tenant_purged' };
  }
}"""
    },
    {
        "id": "ts-hardcore-10-header-trust-auth-bypass",
        "title": "Client Header Forwarded-User Trust (TypeScript / Fastify)",
        "language": "typescript",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Trusts `req.headers['x-forwarded-user']` directly to authenticate user without verifying proxy secret or TLS peer certificate.",
        "code": """fastify.addHook('preHandler', async (request, reply) => {
  const forwardedUser = request.headers['x-forwarded-user'] as string;
  // Flaw: Unconditionally trust client-sent header without gateway token validation
  if (forwardedUser) {
    request.user = { id: forwardedUser, isAuthenticated: true };
    return;
  }
  request.user = { id: null, isAuthenticated: false };
});"""
    },

    # ==========================================================================
    # 4. JAVA (10 Cases)
    # ==========================================================================
    {
        "id": "java-hardcore-01-spring-spel-mismatch",
        "title": "Spring Security SpEL Parameter Name Mismatch (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "SpEL expression checks `#accountId` against principal, but controller parameter is named `targetAccountId`, causing SpEL to evaluate to null/true.",
        "code": """@RestController
@RequestMapping("/api/accounts")
public class UserAccountController {

    @Autowired
    private AccountService accountService;

    // Flaw: SpEL expression references #accountId, but parameter is named targetAccountId
    @PreAuthorize("#accountId == authentication.principal.id or hasRole('ADMIN')")
    @DeleteMapping("/{id}/terminate")
    public ResponseEntity<Void> terminateAccount(@PathVariable("id") Long targetAccountId) {
        accountService.deactivateAccount(targetAccountId);
        return ResponseEntity.noContent().build();
    }
}"""
    },
    {
        "id": "java-hardcore-02-sound-spring-spel",
        "title": "Sound Spring Security SpEL Method Authorization (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: SpEL `#targetAccountId` matches method parameter exactly.",
        "code": """@RestController
@RequestMapping("/api/accounts")
public class UserAccountSecureController {

    @Autowired
    private AccountService accountService;

    @PreAuthorize("#targetAccountId == authentication.principal.id or hasRole('ADMIN')")
    @DeleteMapping("/{id}/terminate")
    public ResponseEntity<Void> terminateAccount(@PathVariable("id") Long targetAccountId) {
        accountService.deactivateAccount(targetAccountId);
        return ResponseEntity.noContent().build();
    }
}"""
    },
    {
        "id": "java-hardcore-03-jpa-unscoped-report",
        "title": "Spring JPA Unscoped Patient Report Retrieval IDOR (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Service method queries report by reportId without checking `report.patientId == currentAuth.getPrincipal().getId()`.",
        "code": """@Service
public class PatientRecordService {

    @Autowired
    private MedicalReportRepository reportRepo;

    public MedicalReport getReport(Long reportId, User principal) {
        // Flaw: Fetches report by ID without asserting ownership by principal
        return reportRepo.findById(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("Report not found"));
    }
}"""
    },
    {
        "id": "java-hardcore-04-sound-jpa-scoped-report",
        "title": "Sound Spring JPA Scoped Retrieval (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `findByIdAndPatientId(reportId, principal.getId())`.",
        "code": """@Service
public class PatientRecordSecureService {

    @Autowired
    private MedicalReportRepository reportRepo;

    public MedicalReport getReport(Long reportId, User principal) {
        return reportRepo.findByIdAndPatientId(reportId, principal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Report not found or unauthorized"));
    }
}"""
    },
    {
        "id": "java-hardcore-05-spring-missing-preauthorize",
        "title": "Missing PreAuthorize on Privileged Service Method (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Privileged batch deletion method in service layer lacks `@PreAuthorize` guard.",
        "code": """@Service
public class SystemMaintenanceService {

    @Autowired
    private AuditRepository auditRepository;

    // Flaw: Destructive service operation lacks security annotation
    public void purgeAuditRecordsBefore(Instant cutoff) {
        auditRepository.deleteByTimestampBefore(cutoff);
    }
}"""
    },
    {
        "id": "java-hardcore-06-sound-spring-preauthorize",
        "title": "Sound PreAuthorize on Privileged Service (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Guarded with `@PreAuthorize(\"hasRole('SYSTEM_ADMIN')\")`.",
        "code": """@Service
public class SystemMaintenanceSecureService {

    @Autowired
    private AuditRepository auditRepository;

    @PreAuthorize("hasRole('SYSTEM_ADMIN')")
    public void purgeAuditRecordsBefore(Instant cutoff) {
        auditRepository.deleteByTimestampBefore(cutoff);
    }
}"""
    },
    {
        "id": "java-hardcore-07-message-digest-timing",
        "title": "MessageDigest String Equality Timing Leak (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Calculates SHA-256 hash but checks with `String.equals()`, leaking timing information instead of using `MessageDigest.isEqual()`.",
        "code": """public boolean verifyApiToken(String clientToken, String storedHash) {
    String computedHash = Hex.encodeHexString(DigestUtils.sha256(clientToken));
    // Flaw: String.equals is not constant-time and leaks comparison timing
    return computedHash.equals(storedHash);
}"""
    },
    {
        "id": "java-hardcore-08-sound-message-digest-is-equal",
        "title": "Sound Constant-Time Digest Verification (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `MessageDigest.isEqual()` for constant-time comparison.",
        "code": """public boolean verifyApiTokenSecure(String clientToken, byte[] storedHashBytes) {
    byte[] computedHashBytes = DigestUtils.sha256(clientToken);
    return MessageDigest.isEqual(computedHashBytes, storedHashBytes);
}"""
    },
    {
        "id": "java-hardcore-09-quarkus-unscoped-tenant-query",
        "title": "Quarkus Panache Unscoped Entity Lookup IDOR (Java / Quarkus)",
        "language": "java",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Fetches tenant invoice using `Invoice.findById(id)` without scoping `tenantId`.",
        "code": """@Path("/api/invoices")
@Authenticated
public class InvoiceResource {

    @GET
    @Path("/{id}")
    public Invoice getInvoice(@PathParam("id") Long id, @Context SecurityContext ctx) {
        // Flaw: findById lacks tenantId filter
        Invoice invoice = Invoice.findById(id);
        if (invoice == null) {
            throw new NotFoundException();
        }
        return invoice;
    }
}"""
    },
    {
        "id": "java-hardcore-10-sound-quarkus-scoped-query",
        "title": "Sound Quarkus Panache Scoped Lookup (Java / Quarkus)",
        "language": "java",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Queries `Invoice.find(\"id = ?1 and tenantId = ?2\", id, tenantId).firstResult()`.",
        "code": """@Path("/api/invoices")
@Authenticated
public class InvoiceSecureResource {

    @GET
    @Path("/{id}")
    public Invoice getInvoice(@PathParam("id") Long id, @Context SecurityContext ctx) {
        String tenantId = ctx.getUserPrincipal().getName();
        Invoice invoice = Invoice.find("id = ?1 and tenantId = ?2", id, tenantId).firstResult();
        if (invoice == null) {
            throw new NotFoundException();
        }
        return invoice;
    }
}"""
    },

    # ==========================================================================
    # 5. C# / .NET (10 Cases)
    # ==========================================================================
    {
        "id": "cs-hardcore-01-ef-unscoped-lookup",
        "title": "ASP.NET Core Entity Framework Unscoped IDOR (C# / .NET Core)",
        "language": "csharp",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Endpoint retrieves confidential student record by ID parameter without asserting `record.SchoolId == user.SchoolId`.",
        "code": """[Authorize]
[HttpGet("api/students/{id}/grades")]
public async Task<IActionResult> GetStudentGrades(int id)
{
    // Flaw: Unscoped query by student ID allows cross-school grade inspection
    var student = await _dbContext.Students
        .Include(s => s.GradeReports)
        .FirstOrDefaultAsync(s => s.Id == id);

    if (student == null)
        return NotFound();

    return Ok(student.GradeReports);
}"""
    },
    {
        "id": "cs-hardcore-02-sound-ef-scoped-lookup",
        "title": "Sound ASP.NET Core EF Scoped Retrieval (C# / .NET Core)",
        "language": "csharp",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses composite query `s.Id == id && s.SchoolId == schoolId`.",
        "code": """[Authorize]
[HttpGet("api/students/{id}/grades")]
public async Task<IActionResult> GetStudentGrades(int id)
{
    var schoolId = int.Parse(User.FindFirst("SchoolId")?.Value ?? "0");
    var student = await _dbContext.Students
        .Include(s => s.GradeReports)
        .FirstOrDefaultAsync(s => s.Id == id && s.SchoolId == schoolId);

    if (student == null)
        return NotFound();

    return Ok(student.GradeReports);
}"""
    },
    {
        "id": "cs-hardcore-03-missing-authorize-controller",
        "title": "Missing Authorize Attribute on Financial Controller (C# / .NET Core)",
        "language": "csharp",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Sensitive fee payment refund endpoint missing `[Authorize]` attribute entirely.",
        "code": """[ApiController]
[Route("api/fees")]
public class FeeManagementController : ControllerBase
{
    private readonly IFeeService _feeService;

    public FeeManagementController(IFeeService feeService) => _feeService = feeService;

    // Flaw: Missing [Authorize(Roles = "Accountant,Admin")] attribute on refund endpoint
    [HttpPost("refund/{transactionId}")]
    public async Task<IActionResult> ProcessRefund(Guid transactionId, [FromBody] RefundRequest request)
    {
        await _feeService.ExecuteRefundAsync(transactionId, request.Amount);
        return Ok(new { status = "refund_processed" });
    }
}"""
    },
    {
        "id": "cs-hardcore-04-sound-authorize-rbac",
        "title": "Sound RBAC Protected Controller (C# / .NET Core)",
        "language": "csharp",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Protected with `[Authorize(Roles = \"Accountant,Admin\")]`.",
        "code": """[Authorize(Roles = "Accountant,Admin")]
[ApiController]
[Route("api/fees")]
public class FeeManagementSecureController : ControllerBase
{
    private readonly IFeeService _feeService;

    public FeeManagementSecureController(IFeeService feeService) => _feeService = feeService;

    [HttpPost("refund/{transactionId}")]
    public async Task<IActionResult> ProcessRefund(Guid transactionId, [FromBody] RefundRequest request)
    {
        await _feeService.ExecuteRefundAsync(transactionId, request.Amount);
        return Ok(new { status = "refund_processed" });
    }
}"""
    },
    {
        "id": "cs-hardcore-05-cryptographic-operations-timing",
        "title": "Cryptographic Key Byte Equality Timing Leak (C# / .NET)",
        "language": "csharp",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Custom loop compares key bytes and breaks early on mismatch, introducing timing attack.",
        "code": """public bool ValidateApiKey(byte[] providedKey, byte[] masterKey)
{
    if (providedKey.Length != masterKey.Length)
        return false;

    // Flaw: Early return loop leaks timing information per byte
    for (int i = 0; i < providedKey.Length; i++)
    {
        if (providedKey[i] != masterKey[i])
            return false;
    }
    return true;
}"""
    },
    {
        "id": "cs-hardcore-06-sound-fixed-time-equals",
        "title": "Sound FixedTimeEquals Constant-Time Comparison (C# / .NET)",
        "language": "csharp",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `CryptographicOperations.FixedTimeEquals(providedKey, masterKey)`.",
        "code": """public bool ValidateApiKeySecure(byte[] providedKey, byte[] masterKey)
{
    return CryptographicOperations.FixedTimeEquals(providedKey, masterKey);
}"""
    },
    {
        "id": "cs-hardcore-07-minimal-api-unscoped-put",
        "title": "Minimal API Unscoped Item Update IDOR (C# / ASP.NET Core)",
        "language": "csharp",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Minimal API endpoint updates item by ID without checking if current user is item creator.",
        "code": """app.MapPut("/api/notes/{id}", async (int id, NoteUpdateDto dto, AppDbContext db, ClaimsPrincipal user) =>
{
    var note = await db.Notes.FindAsync(id);
    if (note is null) return Results.NotFound();

    // Flaw: Updates note content without verifying note.UserId == user.GetUserId()
    note.Title = dto.Title;
    note.Content = dto.Content;
    await db.SaveChangesAsync();

    return Results.Ok(note);
}).RequireAuthorization();"""
    },
    {
        "id": "cs-hardcore-08-sound-minimal-api-scoped-put",
        "title": "Sound Minimal API Scoped Update (C# / ASP.NET Core)",
        "language": "csharp",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Verifies `note.UserId == userId` before allowing modification.",
        "code": """app.MapPut("/api/notes/{id}", async (int id, NoteUpdateDto dto, AppDbContext db, ClaimsPrincipal user) =>
{
    var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var note = await db.Notes.FirstOrDefaultAsync(n => n.Id == id && n.UserId == userId);
    if (note is null) return Results.NotFound();

    note.Title = dto.Title;
    note.Content = dto.Content;
    await db.SaveChangesAsync();

    return Results.Ok(note);
}).RequireAuthorization();"""
    },
    {
        "id": "cs-hardcore-09-role-flag-inversion",
        "title": "Enum Flag Permission Inverted Mask (C# / .NET)",
        "language": "csharp",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "Evaluates `(user.Flags & requiredPermission) == 0`, granting access when permission flag is NOT present.",
        "code": """public bool CheckAccess(UserAccount user, PermissionFlags requiredPermission)
{
    if (user == null || !user.IsActive)
        return false;

    // Flaw: Inverted condition grants access when user does NOT have flag
    if ((user.Flags & requiredPermission) == 0)
    {
        return true;
    }
    return false;
}"""
    },
    {
        "id": "cs-hardcore-10-sound-role-flag-check",
        "title": "Sound Enum Flag Permission Evaluation (C# / .NET)",
        "language": "csharp",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Asserts `(user.Flags & requiredPermission) == requiredPermission`.",
        "code": """public bool CheckAccessSecure(UserAccount user, PermissionFlags requiredPermission)
{
    if (user == null || !user.IsActive || user.IsSuspended)
        return false;

    return (user.Flags & requiredPermission) == requiredPermission;
}"""
    },

    # ==========================================================================
    # 6. PHP (10 Cases)
    # ==========================================================================
    {
        "id": "php-hardcore-01-laravel-unscoped-findOrFail",
        "title": "Laravel Eloquent Direct Resource IDOR (PHP / Laravel)",
        "language": "php",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Queries `Invoice::findOrFail($id)` without scoping `where('user_id', Auth::id())` or calling `$this->authorize('view', $invoice)`.",
        "code": """public function show($id)
{
    // Flaw: Unscoped findOrFail allows any authenticated user to view other users' invoices
    $invoice = Invoice::findOrFail($id);
    return response()->json($invoice);
}"""
    },
    {
        "id": "php-hardcore-02-sound-laravel-policy-check",
        "title": "Sound Laravel Policy Authorized Retrieval (PHP / Laravel)",
        "language": "php",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Calls `$this->authorize('view', $invoice)` enforcing Policy.",
        "code": """public function show($id)
{
    $invoice = Invoice::findOrFail($id);
    $this->authorize('view', $invoice);
    return response()->json($invoice);
}"""
    },
    {
        "id": "php-hardcore-03-header-admin-spoof",
        "title": "HTTP Header Administrative Spoofing (PHP / Standard)",
        "language": "php",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Trusts `$_SERVER['HTTP_X_ADMIN_AUTH'] === 'true'` directly without cryptographic signature validation.",
        "code": """function checkIsAdminUser(): bool {
    // Flaw: Client-supplied HTTP header directly sets admin session state
    if (isset($_SERVER['HTTP_X_ADMIN_AUTH']) && $_SERVER['HTTP_X_ADMIN_AUTH'] === 'true') {
        return true;
    }
    return false;
}"""
    },
    {
        "id": "php-hardcore-04-sound-hash-equals-gateway",
        "title": "Sound hash_equals Constant-Time Signature Verification (PHP / Standard)",
        "language": "php",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `hash_equals($expectedSig, $clientSig)` across HMAC-SHA256 digests.",
        "code": """function verifyGatewaySignature(string $payload, string $clientSig, string $secret): bool {
    $expectedSig = hash_hmac('sha256', $payload, $secret);
    return hash_equals($expectedSig, $clientSig);
}"""
    },
    {
        "id": "php-hardcore-05-unprotected-database-truncate",
        "title": "Missing Authorization on System Reset Route (PHP / Slim)",
        "language": "php",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Sensitive database reset endpoint exposed without session or API token verification middleware.",
        "code": """$app->post('/api/admin/reset-database', function (Request $request, Response $response) {
    $body = $request->getParsedBody();
    // Flaw: Destructive route missing authentication middleware
    if (($body['confirm'] ?? '') === 'RESET_ALL') {
        DB::statement('TRUNCATE TABLE users, orders, balances');
        return $response->withJson(['status' => 'system_reset']);
    }
    return $response->withStatus(400)->withJson(['error' => 'Confirmation required']);
});"""
    },
    {
        "id": "php-hardcore-06-sound-protected-slim-route",
        "title": "Sound Auth & Role Middleware Protected Route (PHP / Slim)",
        "language": "php",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Guarded with `->add(new AdminAuthMiddleware())`.",
        "code": """$app->post('/api/admin/reset-database', function (Request $request, Response $response) {
    $body = $request->getParsedBody();
    if (($body['confirm'] ?? '') === 'RESET_ALL') {
        DB::statement('TRUNCATE TABLE users, orders, balances');
        return $response->withJson(['status' => 'system_reset']);
    }
    return $response->withStatus(400)->withJson(['error' => 'Confirmation required']);
})->add(new AdminAuthMiddleware());"""
    },
    {
        "id": "php-hardcore-07-eloquent-bulk-delete-idor",
        "title": "Laravel Eloquent Bulk Delete IDOR (PHP / Laravel)",
        "language": "php",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Deletes array of document IDs using `Document::whereIn('id', $ids)->delete()` without scoping `where('user_id', Auth::id())`.",
        "code": """public function bulkDelete(Request $request)
{
    $ids = $request->input('document_ids', []);
    // Flaw: Deletes documents across all users matching IDs
    Document::whereIn('id', $ids)->delete();
    return response()->json(['status' => 'deleted', 'count' => count($ids)]);
}"""
    },
    {
        "id": "php-hardcore-08-sound-eloquent-scoped-bulk-delete",
        "title": "Sound Laravel Scoped Bulk Deletion (PHP / Laravel)",
        "language": "php",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Restricts bulk delete to `where('user_id', Auth::id())`.",
        "code": """public function bulkDeleteSecure(Request $request)
{
    $ids = $request->input('document_ids', []);
    Document::where('user_id', Auth::id())
        ->whereIn('id', $ids)
        ->delete();
    return response()->json(['status' => 'deleted', 'count' => count($ids)]);
}"""
    },
    {
        "id": "php-hardcore-09-symmetric-string-compare-timing",
        "title": "Standard String Equality Token Check (PHP / Symfony)",
        "language": "php",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Compares secret webhook token with `===`, creating timing side-channel discrepancy.",
        "code": """public function handleWebhook(Request $request): Response
{
    $token = $request->headers->get('X-Webhook-Token');
    $secret = $this->getParameter('webhook_secret');
    // Flaw: Strict equality operator === is vulnerable to timing attacks
    if ($token !== $secret) {
        return new JsonResponse(['error' => 'Unauthorized'], 401);
    }
    return new JsonResponse(['status' => 'received']);
}"""
    },
    {
        "id": "php-hardcore-10-sound-symfony-hash-equals",
        "title": "Sound Symfony Hash Equals Verification (PHP / Symfony)",
        "language": "php",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses `hash_equals($secret, $token)`.",
        "code": """public function handleWebhookSecure(Request $request): Response
{
    $token = (string) $request->headers->get('X-Webhook-Token');
    $secret = (string) $this->getParameter('webhook_secret');
    if (!hash_equals($secret, $token)) {
        return new JsonResponse(['error' => 'Unauthorized'], 401);
    }
    return new JsonResponse(['status' => 'received']);
}"""
    }
]


def get_hardcore_benchmark_cases() -> List[Dict[str, Any]]:
    """Return all 60 verified hardcore adversarial test cases."""
    return HARDCORE_BENCHMARK_CASES


if __name__ == "__main__":
    cases = get_hardcore_benchmark_cases()
    print(f"Total Hardcore Benchmark Cases: {len(cases)}")
    vuln_count = sum(1 for c in cases if c["true_is_vulnerable"])
    clean_count = sum(1 for c in cases if not c["true_is_vulnerable"])
    print(f"• Vulnerable Cases: {vuln_count}")
    print(f"• Clean Hard Negatives: {clean_count}")
    langs = {}
    for c in cases:
        langs[c["language"]] = langs.get(c["language"], 0) + 1
    print("• Language Breakdown:", langs)
