package authusecase

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/demola234/defifundr/config"
	"github.com/demola234/defifundr/infrastructure/common/logging"
	commons "github.com/demola234/defifundr/infrastructure/hash"
	userdomain "github.com/demola234/defifundr/internal/features/user/domain"
	authdomain "github.com/demola234/defifundr/internal/features/auth/domain"
	authport "github.com/demola234/defifundr/internal/features/auth/port"
	userport "github.com/demola234/defifundr/internal/features/user/port"
	token "github.com/demola234/defifundr/pkg/token"
	"github.com/demola234/defifundr/pkg/tracing"
	random "github.com/demola234/defifundr/pkg/random"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type authUseCase struct {
	userRepo     userport.UserRepository
	sessionRepo  authport.SessionRepository
	oauthRepo    authport.OAuthRepository
	walletRepo   authport.WalletRepository
	securityRepo authport.SecurityRepository
	emailService authport.EmailService
	tokenMaker   token.Maker
	config       config.Config
	logger       logging.Logger
	otpRepo      authport.OTPRepository
	userService  userport.UserService
}

// New creates a new AuthService.
func New(
	userRepo userport.UserRepository,
	sessionRepo authport.SessionRepository,
	oauthRepo authport.OAuthRepository,
	walletRepo authport.WalletRepository,
	securityRepo authport.SecurityRepository,
	emailService authport.EmailService,
	tokenMaker token.Maker,
	cfg config.Config,
	logger logging.Logger,
	otpRepo authport.OTPRepository,
	userService userport.UserService,
) authport.AuthService {
	return &authUseCase{
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		oauthRepo:    oauthRepo,
		walletRepo:   walletRepo,
		securityRepo: securityRepo,
		emailService: emailService,
		tokenMaker:   tokenMaker,
		config:       cfg,
		logger:       logger,
		otpRepo:      otpRepo,
		userService:  userService,
	}
}

// GetUserRepository exposes the user repository (used by MFA middleware).
func (a *authUseCase) GetUserRepository() userport.UserRepository {
	return a.userRepo
}

// SetupMFA generates a TOTP secret for a user.
func (a *authUseCase) SetupMFA(ctx context.Context, userID uuid.UUID) (string, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "SetupMFA")
	defer span.End()

	user, err := a.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "DefiFundr",
		AccountName: user.Email,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	if err := a.userRepo.SetMFASecret(ctx, userID, key.Secret()); err != nil {
		return "", fmt.Errorf("failed to store MFA secret: %w", err)
	}

	a.LogSecurityEvent(ctx, "mfa_setup_initiated", userID, map[string]any{"time": time.Now().Format(time.RFC3339)})
	return key.URL(), nil
}

// VerifyMFA validates a TOTP code.
func (a *authUseCase) VerifyMFA(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "VerifyMFA")
	defer span.End()

	secret, err := a.userRepo.GetMFASecret(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get MFA secret: %w", err)
	}
	valid := totp.Validate(code, secret)
	a.LogSecurityEvent(ctx, "mfa_verification", userID, map[string]any{"success": valid})
	return valid, nil
}

// Login authenticates a user with email/password or OAuth.
func (a *authUseCase) Login(ctx context.Context, email string, user userdomain.User, password string) (*userdomain.User, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "Login")
	defer span.End()

	if user.AuthProvider == "email" {
		if password == "" {
			return nil, errors.New("password is required for email authentication")
		}
		existingUser, err := a.userRepo.GetUserByEmail(ctx, email)
		if err != nil || existingUser == nil {
			return nil, errors.New("user not found")
		}
		checked, err := commons.CheckPassword(password, existingUser.PasswordHash)
		if err != nil || !checked {
			return nil, errors.New("invalid password")
		}
		return existingUser, nil
	} else if user.AuthProvider != "" && user.WebAuthToken != "" {
		claims, err := a.oauthRepo.ValidateWebAuthToken(ctx, user.WebAuthToken)
		if err != nil {
			return nil, fmt.Errorf("invalid authentication token: %w", err)
		}
		if claims.Email != "" {
			user.Email = claims.Email
		}
	} else {
		return nil, errors.New("missing authentication credentials")
	}

	existingUser, err := a.userRepo.GetUserByEmail(ctx, user.Email)
	if err != nil || existingUser == nil {
		return nil, errors.New("email not registered")
	}
	return existingUser, nil
}

// RegisterUser creates a new user account.
func (a *authUseCase) RegisterUser(ctx context.Context, user userdomain.User, passwordStr string) (*userdomain.User, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "RegisterUser")
	defer span.End()

	if user.AuthProvider == "email" {
		if passwordStr == "" {
			return nil, errors.New("password is required for email authentication")
		}
		hashedPassword, err := commons.HashPassword(passwordStr)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		user.PasswordHash = hashedPassword
	} else if user.AuthProvider != "" && user.WebAuthToken != "" {
		claims, err := a.oauthRepo.ValidateWebAuthToken(ctx, user.WebAuthToken)
		if err != nil {
			return nil, fmt.Errorf("invalid authentication token: %w", err)
		}
		if claims.Email != "" {
			user.Email = claims.Email
		}
		if claims.Name != "" {
			parts := strings.Split(claims.Name, " ")
			user.FirstName = parts[0]
			if len(parts) > 1 {
				user.LastName = strings.Join(parts[1:], " ")
			}
		}
		if claims.ProfileImage != "" {
			pi := claims.ProfileImage
			user.ProfilePicture = &pi
		}
		if claims.VerifierID != "" {
			user.ProviderID = claims.VerifierID
		}
	} else {
		return nil, errors.New("missing authentication credentials")
	}

	existing, err := a.userRepo.GetUserByEmail(ctx, user.Email)
	if err == nil && existing != nil {
		return nil, errors.New("email already registered")
	}

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	return a.userRepo.CreateUser(ctx, user)
}

// RegisterPersonalDetails updates a user's personal details.
func (a *authUseCase) RegisterPersonalDetails(ctx context.Context, user userdomain.User) (*userdomain.User, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "RegisterPersonalDetails")
	defer span.End()

	existing, err := a.userRepo.GetUserByID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	updated := *existing
	updated.Nationality = user.Nationality
	if user.AccountType != "" {
		updated.AccountType = user.AccountType
	}
	if user.PersonalAccountType != "" {
		updated.PersonalAccountType = user.PersonalAccountType
	}
	if user.PhoneNumber != nil {
		updated.PhoneNumber = user.PhoneNumber
	}
	return a.userRepo.UpdateUserPersonalDetails(ctx, updated)
}

// RegisterAddressDetails updates a user's address details.
func (a *authUseCase) RegisterAddressDetails(ctx context.Context, user userdomain.User) (*userdomain.User, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "RegisterAddressDetails")
	defer span.End()

	existing, err := a.userRepo.GetUserByID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	updated := *existing
	if user.UserAddress != nil {
		updated.UserAddress = user.UserAddress
	}
	if user.City != "" {
		updated.City = user.City
	}
	if user.PostalCode != "" {
		updated.PostalCode = user.PostalCode
	}
	return a.userRepo.UpdateUserAddressDetails(ctx, updated)
}

// RegisterBusinessDetails updates a user's business details.
func (a *authUseCase) RegisterBusinessDetails(ctx context.Context, companyInfo userdomain.CompanyInfo) (*userdomain.CompanyInfo, error) {
	existing, err := a.userRepo.GetUserCompanyInfo(ctx, companyInfo.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company info: %w", err)
	}
	updated := *existing
	updated.CompanyName = companyInfo.CompanyName
	if companyInfo.CompanyDescription != nil {
		updated.CompanyDescription = companyInfo.CompanyDescription
	}
	if companyInfo.CompanyHeadquarters != nil {
		updated.CompanyHeadquarters = companyInfo.CompanyHeadquarters
	}
	if companyInfo.CompanyIndustry != nil {
		updated.CompanyIndustry = companyInfo.CompanyIndustry
	}
	if companyInfo.CompanySize != nil {
		updated.CompanySize = companyInfo.CompanySize
	}
	if companyInfo.AccountType != "" {
		updated.AccountType = companyInfo.AccountType
	}
	return a.userRepo.UpdateUserBusinessDetails(ctx, updated)
}

// GetProfileCompletionStatus calculates profile completion percentage.
func (a *authUseCase) GetProfileCompletionStatus(ctx context.Context, userID uuid.UUID) (*authdomain.ProfileCompletion, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "GetProfileCompletionStatus")
	defer span.End()

	user, err := a.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	type fieldCheck struct {
		name     string
		required bool
		value    any
	}
	fields := []fieldCheck{
		{"First Name", true, user.FirstName != ""},
		{"Last Name", true, user.LastName != ""},
		{"Nationality", true, user.Nationality != "" && user.Nationality != "unknown"},
		{"Address", true, user.UserAddress != nil && *user.UserAddress != ""},
		{"City", true, user.City != ""},
		{"Postal Code", true, user.PostalCode != ""},
	}

	var completed, required int
	var missing []string
	for _, f := range fields {
		if f.required {
			required++
			done := false
			if b, ok := f.value.(bool); ok {
				done = b
			} else {
				done = f.value != nil
			}
			if done {
				completed++
			} else {
				missing = append(missing, f.name)
			}
		}
	}

	pct := 0
	if required > 0 {
		pct = (completed * 100) / required
	}
	var actions []string
	if len(missing) > 0 {
		actions = append(actions, "complete_profile")
	}

	return &authdomain.ProfileCompletion{
		UserID:               userID,
		CompletionPercentage: pct,
		MissingFields:        missing,
		RequiredActions:      actions,
	}, nil
}

// AuthenticateWithWeb3 handles unified Web3Auth login/registration.
func (a *authUseCase) AuthenticateWithWeb3(ctx context.Context, webAuthToken, userAgent, clientIP string) (*userdomain.User, *authdomain.Session, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "AuthenticateWithWeb3")
	defer span.End()

	claims, err := a.oauthRepo.ValidateWebAuthToken(ctx, webAuthToken)
	if err != nil {
		span.RecordError(err)
		return nil, nil, err
	}

	email := claims.Email
	if email == "" {
		return nil, nil, errors.New("email not provided in Web3Auth token")
	}

	existingUser, err := a.userRepo.GetUserByEmail(ctx, email)
	var user *userdomain.User
	isNewUser := false

	if err != nil || existingUser == nil {
		firstName, lastName := extractNameFromClaims(claims)
		profileImage := claims.ProfileImage
		authProvider := mapVerifierToProvider(claims.Verifier)
		newUser := userdomain.User{
			ID:                  uuid.New(),
			Email:               email,
			FirstName:           firstName,
			LastName:            lastName,
			ProfilePicture:      &profileImage,
			ProviderID:          claims.VerifierID,
			AuthProvider:        string(authProvider),
			AccountType:         "personal",
			PersonalAccountType: "user",
			Nationality:         "unknown",
		}
		user, err = a.userRepo.CreateUser(ctx, newUser)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create user: %w", err)
		}
		isNewUser = true
		a.LogSecurityEvent(ctx, "user_registered", user.ID, map[string]any{"provider": user.AuthProvider, "email": user.Email})
	} else {
		user = existingUser
		updateNeeded := false
		if claims.ProfileImage != "" && (user.ProfilePicture == nil || *user.ProfilePicture != claims.ProfileImage) {
			pi := claims.ProfileImage
			user.ProfilePicture = &pi
			updateNeeded = true
		}
		if user.FirstName == "" && user.LastName == "" {
			user.FirstName, user.LastName = extractNameFromClaims(claims)
			updateNeeded = true
		}
		if updateNeeded {
			a.userRepo.UpdateUser(ctx, *user)
		}
	}

	if len(claims.Wallets) > 0 {
		for _, wallet := range claims.Wallets {
			if err := a.processWallet(ctx, user.ID, wallet); err != nil {
				a.logger.Warn("Failed to process wallet", map[string]any{"user_id": user.ID, "error": err.Error()})
			}
		}
	}

	session, err := a.CreateSession(ctx, user.ID, userAgent, clientIP, webAuthToken, user.Email, "web3auth")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	a.LogSecurityEvent(ctx, "user_login", user.ID, map[string]any{"provider": user.AuthProvider, "ip": clientIP, "is_new_user": isNewUser})
	go a.detectSuspiciousActivity(context.Background(), user.ID, clientIP, userAgent)

	return user, session, nil
}

func (a *authUseCase) processWallet(ctx context.Context, userID uuid.UUID, wallet authdomain.Wallet) error {
	if wallet.PublicKey == "" {
		return nil
	}
	existing, err := a.walletRepo.GetWalletByAddress(ctx, wallet.PublicKey)
	if err != nil {
		return fmt.Errorf("error checking wallet: %w", err)
	}
	if existing != nil && existing.UserID == userID {
		return nil
	}
	if existing != nil && existing.UserID != userID {
		a.LogSecurityEvent(ctx, "wallet_conflict", userID, map[string]any{"wallet_address": wallet.PublicKey})
		return fmt.Errorf("wallet already linked to another account")
	}
	chain := "ethereum"
	if wallet.Type != "" && wallet.Type != "hex" {
		chain = strings.ToLower(wallet.Type)
	}
	return a.LinkWallet(ctx, userID, wallet.PublicKey, wallet.Type, chain)
}

// LinkWallet links a wallet to a user account.
func (a *authUseCase) LinkWallet(ctx context.Context, userID uuid.UUID, walletAddress, walletType, chain string) error {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "LinkWallet")
	defer span.End()

	a.LogSecurityEvent(ctx, "wallet_linked", userID, map[string]any{"wallet_address": walletAddress, "wallet_type": walletType, "chain": chain})
	return nil
}

// GetUserWallets retrieves all wallets for a user.
func (a *authUseCase) GetUserWallets(ctx context.Context, userID uuid.UUID) ([]authdomain.UserWallet, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "GetUserWallets")
	defer span.End()
	return a.walletRepo.GetWalletsByUserID(ctx, userID)
}

// CreateSession creates a new session with tokens.
func (a *authUseCase) CreateSession(ctx context.Context, userID uuid.UUID, userAgent, clientIP, webOAuthClientID, email, loginType string) (*authdomain.Session, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "CreateSession")
	defer span.End()

	accessToken, _, err := a.tokenMaker.CreateToken(email, userID, a.config.AccessTokenDuration, loginType)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	refreshToken, payload, err := a.tokenMaker.CreateToken(email, userID, a.config.RefreshTokenDuration, loginType)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	session := authdomain.Session{
		ID:               uuid.New(),
		UserID:           userID,
		RefreshToken:     refreshToken,
		OAuthAccessToken: accessToken,
		UserAgent:        userAgent,
		ClientIP:         clientIP,
		IsBlocked:        false,
		MFAEnabled:       false,
		UserLoginType:    loginType,
		ExpiresAt:        time.Now().Add(a.config.AccessTokenDuration),
		CreatedAt:        time.Now(),
	}
	if webOAuthClientID != "" {
		session.WebOAuthClientID = &webOAuthClientID
	}

	userSession, err := a.sessionRepo.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	a.logger.Info("Session created", map[string]any{"session_id": session.ID, "expires_at": payload.ExpiredAt})
	return userSession, nil
}

// GetActiveDevices returns all active devices for a user.
func (a *authUseCase) GetActiveDevices(ctx context.Context, userID uuid.UUID) ([]authdomain.DeviceInfo, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "GetActiveDevices")
	defer span.End()

	sessions, err := a.sessionRepo.GetActiveSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}

	devices := make([]authdomain.DeviceInfo, 0, len(sessions))
	for _, s := range sessions {
		devices = append(devices, authdomain.DeviceInfo{
			SessionID:       s.ID,
			Browser:         parseUserAgent(s.UserAgent),
			OperatingSystem: extractOS(s.UserAgent),
			DeviceType:      determineDeviceType(s.UserAgent),
			IPAddress:       s.ClientIP,
			LoginType:       s.UserLoginType,
			LastUsed:        time.Now(),
			CreatedAt:       s.CreatedAt,
		})
	}
	return devices, nil
}

// RevokeSession revokes a specific session.
func (a *authUseCase) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "RevokeSession")
	defer span.End()

	session, err := a.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}
	if session.UserID != userID {
		return errors.New("session does not belong to user")
	}
	if err := a.sessionRepo.BlockSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to block session: %w", err)
	}
	a.LogSecurityEvent(ctx, "session_revoked", userID, map[string]any{"session_id": sessionID})
	return nil
}

// Logout revokes the current session.
func (a *authUseCase) Logout(ctx context.Context, sessionID uuid.UUID) error {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "Logout")
	defer span.End()
	return a.sessionRepo.DeleteSession(ctx, sessionID)
}

// RefreshToken refreshes an access token.
func (a *authUseCase) RefreshToken(ctx context.Context, refreshToken, userAgent, clientIP string) (*authdomain.Session, string, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "RefreshToken")
	defer span.End()

	session, err := a.sessionRepo.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get session: %w", err)
	}
	if session == nil || session.IsBlocked || time.Now().After(session.ExpiresAt) {
		return nil, "", errors.New("invalid or expired refresh token")
	}

	user, err := a.userRepo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get user: %w", err)
	}

	accessToken, _, err := a.tokenMaker.CreateToken(user.Email, user.ID, a.config.AccessTokenDuration, user.AccountType)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create access token: %w", err)
	}

	newRefreshToken, _, err := a.tokenMaker.CreateToken(user.Email, user.ID, a.config.RefreshTokenDuration, user.AccountType)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create refresh token: %w", err)
	}

	updatedSession, err := a.sessionRepo.UpdateRefreshToken(ctx, session.ID, newRefreshToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to update refresh token: %w", err)
	}

	a.LogSecurityEvent(ctx, "token_refreshed", user.ID, map[string]any{"session_id": session.ID, "ip": clientIP})
	return updatedSession, accessToken, nil
}

// GetUserByID retrieves a user by ID.
func (a *authUseCase) GetUserByID(ctx context.Context, userID uuid.UUID) (*userdomain.User, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "GetUserByID")
	defer span.End()
	user, err := a.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email.
func (a *authUseCase) GetUserByEmail(ctx context.Context, email string) (*userdomain.User, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "GetUserByEmail")
	defer span.End()
	return a.userRepo.GetUserByEmail(ctx, email)
}

// CheckEmailExists checks if an email is registered.
func (a *authUseCase) CheckEmailExists(ctx context.Context, email string) (bool, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "CheckEmailExists")
	defer span.End()
	return a.userRepo.CheckEmailExists(ctx, email)
}

// LogSecurityEvent logs a security event.
func (a *authUseCase) LogSecurityEvent(ctx context.Context, eventType string, userID uuid.UUID, metadata map[string]any) error {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "LogSecurityEvent")
	defer span.End()

	clientIP := ""
	if v := ctx.Value("client_ip"); v != nil {
		if ip, ok := v.(string); ok {
			clientIP = ip
		}
	}
	userAgent := ""
	if v := ctx.Value("user_agent"); v != nil {
		if ua, ok := v.(string); ok {
			userAgent = ua
		}
	}

	event := authdomain.SecurityEvent{
		ID:        uuid.New(),
		UserID:    userID,
		EventType: eventType,
		IPAddress: clientIP,
		UserAgent: userAgent,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}
	return a.securityRepo.LogSecurityEvent(ctx, event)
}

// GetUserSecurityEvents retrieves security events for a user.
func (a *authUseCase) GetUserSecurityEvents(ctx context.Context, userID uuid.UUID) ([]authdomain.SecurityEvent, error) {
	ctx, span := tracing.Tracer("auth-usecase").Start(ctx, "GetUserSecurityEvents")
	defer span.End()
	return a.securityRepo.GetRecentLoginsByUserID(ctx, userID, 20)
}

// InitiatePasswordReset starts the password reset process.
func (a *authUseCase) InitiatePasswordReset(ctx context.Context, email string) error {
	user, err := a.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil // Don't reveal if email exists
	}
	if user.AuthProvider != "email" {
		return nil
	}

	otpCode := random.RandomOtp()
	otp := authdomain.OTPVerification{
		ID:          uuid.New(),
		UserID:      user.ID,
		Purpose:     authdomain.OTPPurposePasswordReset,
		OTPCode:     otpCode,
		MaxAttempts: 5,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}

	if _, err := a.otpRepo.CreateOTP(ctx, otp); err != nil {
		return nil // Don't reveal internal errors
	}
	if err := a.emailService.SendPasswordResetEmail(ctx, email, user.FirstName, otpCode); err != nil {
		a.logger.Error("Failed to send password reset email", err, map[string]any{"email": email})
	}
	a.LogSecurityEvent(ctx, "password_reset_initiated", user.ID, map[string]any{"email": email})
	return nil
}

// VerifyResetOTP verifies a password reset OTP without invalidating it.
func (a *authUseCase) VerifyResetOTP(ctx context.Context, email, code string) error {
	user, err := a.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return errors.New("invalid email or OTP")
	}
	otp, err := a.otpRepo.GetOTPByUserIDAndPurpose(ctx, user.ID, authdomain.OTPPurposePasswordReset)
	if err != nil {
		return errors.New("invalid or expired OTP")
	}
	if time.Now().After(otp.ExpiresAt) {
		return errors.New("OTP has expired")
	}
	if otp.AttemptsMade >= otp.MaxAttempts {
		return errors.New("maximum attempts exceeded")
	}
	if otp.OTPCode != code {
		a.otpRepo.IncrementAttempts(ctx, otp.ID)
		return errors.New("invalid OTP")
	}
	a.LogSecurityEvent(ctx, "password_reset_otp_verified", user.ID, map[string]any{"email": email})
	return nil
}

// ResetPassword verifies OTP and resets the password.
func (a *authUseCase) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	user, err := a.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return errors.New("invalid email")
	}
	otp, err := a.otpRepo.GetOTPByUserIDAndPurpose(ctx, user.ID, authdomain.OTPPurposePasswordReset)
	if err != nil {
		return errors.New("invalid or expired OTP")
	}
	if time.Now().After(otp.ExpiresAt) {
		return errors.New("OTP has expired")
	}
	if otp.AttemptsMade >= otp.MaxAttempts {
		return errors.New("maximum attempts exceeded")
	}
	if otp.OTPCode != code {
		a.otpRepo.IncrementAttempts(ctx, otp.ID)
		return errors.New("invalid OTP")
	}

	if err := a.userService.ResetUserPassword(ctx, user.ID, newPassword); err != nil {
		return fmt.Errorf("failed to reset password: %w", err)
	}
	a.otpRepo.VerifyOTP(ctx, otp.ID, code)
	a.sessionRepo.BlockAllUserSessions(ctx, user.ID)
	a.LogSecurityEvent(ctx, "password_reset_completed", user.ID, map[string]any{"email": email})
	return nil
}

// detectSuspiciousActivity runs in background to check for unusual logins.
func (a *authUseCase) detectSuspiciousActivity(ctx context.Context, userID uuid.UUID, clientIP, userAgent string) {
	previous, err := a.securityRepo.GetRecentLoginsByUserID(ctx, userID, 5)
	if err != nil || len(previous) == 0 {
		return
	}
	isNewIP, isNewDevice := true, true
	for _, login := range previous {
		if login.IPAddress == clientIP {
			isNewIP = false
		}
		if login.UserAgent == userAgent {
			isNewDevice = false
		}
	}
	if isNewIP || isNewDevice {
		user, err := a.userRepo.GetUserByID(ctx, userID)
		if err != nil {
			return
		}
		deviceInfo := parseUserAgent(userAgent)
		loginTime := time.Now().Format(time.RFC1123)
		if a.emailService != nil {
			go func() {
				a.emailService.SendBatchUpdate(
					context.Background(),
					[]string{user.Email},
					"New Login Detected",
					fmt.Sprintf("New login from %s at %s.", deviceInfo, loginTime),
				)
			}()
		}
		a.securityRepo.LogSecurityEvent(ctx, authdomain.SecurityEvent{
			ID:        uuid.New(),
			UserID:    userID,
			IPAddress: clientIP,
			UserAgent: userAgent,
			EventType: "new_ip_device_detected",
			Metadata:  map[string]any{"device": deviceInfo, "time": loginTime},
			Timestamp: time.Now(),
		})
	}
}

// --- helpers ---

func extractNameFromClaims(claims *authdomain.Web3AuthClaims) (string, string) {
	if claims.Name == "" {
		return "User", ""
	}
	parts := strings.Split(claims.Name, " ")
	first := parts[0]
	var last string
	if len(parts) > 1 {
		last = strings.Join(parts[1:], " ")
	}
	return first, last
}

func mapVerifierToProvider(verifier string) authdomain.AuthProvider {
	lv := strings.ToLower(verifier)
	switch {
	case strings.Contains(lv, "google"):
		return authdomain.GoogleProvider
	case strings.Contains(lv, "facebook"):
		return authdomain.FacebookProvider
	case strings.Contains(lv, "apple"):
		return authdomain.AppleProvider
	case strings.Contains(lv, "twitter"):
		return authdomain.TwitterProvider
	case strings.Contains(lv, "discord"):
		return authdomain.DiscordProvider
	}
	return authdomain.Web3AuthProvider
}

func parseUserAgent(ua string) string {
	lv := strings.ToLower(ua)
	browser := "Unknown Browser"
	switch {
	case strings.Contains(lv, "chrome"):
		browser = "Chrome"
	case strings.Contains(lv, "firefox"):
		browser = "Firefox"
	case strings.Contains(lv, "safari") && !strings.Contains(lv, "chrome"):
		browser = "Safari"
	case strings.Contains(lv, "edge"):
		browser = "Edge"
	}
	device := "Unknown Device"
	switch {
	case strings.Contains(lv, "iphone"):
		device = "iPhone"
	case strings.Contains(lv, "ipad"):
		device = "iPad"
	case strings.Contains(lv, "android"):
		device = "Android Device"
	case strings.Contains(lv, "macintosh"):
		device = "Mac"
	case strings.Contains(lv, "windows"):
		device = "Windows PC"
	case strings.Contains(lv, "linux"):
		device = "Linux PC"
	}
	return fmt.Sprintf("%s on %s", browser, device)
}

func extractOS(ua string) string {
	lv := strings.ToLower(ua)
	switch {
	case strings.Contains(lv, "windows"):
		return "Windows"
	case strings.Contains(lv, "macintosh"), strings.Contains(lv, "mac os"):
		return "MacOS"
	case strings.Contains(lv, "linux") && !strings.Contains(lv, "android"):
		return "Linux"
	case strings.Contains(lv, "android"):
		return "Android"
	case strings.Contains(lv, "iphone"), strings.Contains(lv, "ipad"), strings.Contains(lv, "ios"):
		return "iOS"
	}
	return "Unknown OS"
}

func determineDeviceType(ua string) string {
	lv := strings.ToLower(ua)
	if strings.Contains(lv, "iphone") || (strings.Contains(lv, "android") && strings.Contains(lv, "mobile")) {
		return "Mobile"
	}
	if strings.Contains(lv, "ipad") || (strings.Contains(lv, "android") && !strings.Contains(lv, "mobile")) {
		return "Tablet"
	}
	return "Desktop"
}
