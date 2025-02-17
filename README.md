# payloadcms-2fa-auth
code snippet for enabling or using 2 FA authentication with payload cms


### Add a checkbox field and UI in a collection
```
fields: [{
      name: 'Account',
      type: 'ui',
      admin: {
        components: {
          Field: MFAButton,
        },      },
    },
   {
      name: 'isMfaEnabled', // required
      type: 'checkbox', // required
    }]
```

### Add custom endpoint in collection
```
 endpoints: [
    {
      path: '/qr',
      method: EAxiosRequestMethod.GET,
      handler: getQRCode,
    },
    {
      path: '/qr/verify',
      method: EAxiosRequestMethod.POST,
      handler: verifyKeyCode,
    },
]
```

### Here is the get getQRCode
```
export const getQRCode = async (req, res, next) => {
  try {
    const user = req.user;

    const token = speakeasy.generateSecret().base32;

    const otpPathURL = speakeasy.otpauthURL({
      label: user?.email,
      secret: user?.twoFactorTempSecret ? user?.twoFactorTempSecret : token,
      encoding: 'base32',
    });

    if (!user?.twoFactorTempSecret) {
      await payload.update({
        collection: ECollections.ADMIN_USERS,
        id: user.id,
        data: {
          twoFactorTempSecret: token,
        },
      });
    }

    const qrCodeUrl = await qrcode.toDataURL(otpPathURL);

    return res.status(200).send({ qrCodeUrl: qrCodeUrl });
  } catch (error) {
    return res.status(400).json({
      message: req.i18n.t('mfa.validation.error'),
    });
  }
};
```

### Here is the verifyKeyCode

```
export const verifyKeyCode = async (req, res, next) => {
  try {
    const user = req.user;

    const userToken = req?.body?.key;
    if (!userToken) {
      return await res.status(404).json({
        message: req.i18n.t('mfa.validation.token.not_found'),
      });
    }
    if (
      !speakeasy.totp.verify({
        secret: user.twoFactorTempSecret,
        encoding: 'base32',
        token: userToken,
      })
    ) {
      return await res.status(404).json({
        message: req.i18n.t('mfa.validation.token.wrong_token'),
      });
    } else {
      await payload.update({
        collection: ECollections.ADMIN_USERS,
        id: user.id,
        data: {
          isMfaEnabled: true,
        },
      });
      return await res.status(200).json({
        message: req.i18n.t('mfa.validation.enable.success'),
        data: user,
      });
    }
  } catch (error) {
    return res.status(400).json({
      message: req.i18n.t('mfa.validation.enable.error'),
    });
  }
};
```

### Here is the checkIsMFAEnabled

```
export const checkIsMFAEnabled = async (req, res, next) => {
  try {
    const body = req.body;
    const user: any = (
      await payload.find({
        collection: ECollections.ADMIN_USERS,
        where: {
          email: {
            equals: body.email,
          },
        },
      })
    )?.docs[0];

    return res.status(200).send({ isMfaEnabled: user?.isMfaEnabled ?? false });
  } catch (error) {
    return res.status(400).json({
      message: req.i18n.t('mfa.validation.error'),
    });
  }
};
```

### Here is the MFAButton Custom Component

```
function MFAButton() {
  const { t, i18n } = useTranslation('translation');
  const locale = useLocale();

  const { register, handleSubmit, watch } = useForm();
  const [qrCode, setQrCode] = useState(null);
  const [user, setUser] = useState(null);

  const key = watch('key');

  const userService = new UserService();

  const getQRCode = async () => {
    try {
      const data = await userService.getQRCode();
      setQrCode(data?.qrCodeUrl ?? null);
    } catch (error) {
      toast.error(t('mfa.validation.qr_generate.error'));
    }
  };

  const handleKeyValidate = async () => {
    try {
      if (key) {
        const data = await userService.verifyQRCode(key);
        if (data?.data) {
          getProfile();
          toast.success(data?.message ?? t('mfa.validation.enable.success'));
        } else {
          toast.error(data?.message ?? t('mfa.validation.enable.error'));
        }
      }
    } catch (error) {
      toast.error(error?.message ?? t('mfa.validation.enable.error'));
    }
  };

  const getProfile = async () => {
    try {
      const data = await userService.getProfile();
      setUser(data?.user ?? null);
      setQrCode(null);
    } catch (error) {
      toast.error(t('mfa.validation.profile_not_retrieved'));
    }
  };

  useEffect(() => {
    getProfile();
  }, []);

  return (
    <form onSubmit={handleSubmit(handleKeyValidate)} className="render-fields">
      <div>
        <button
          disabled={user?.isMfaEnabled ?? false}
          type="button"
          onClick={getQRCode}
          className="btn btn--style-primary btn--icon-style-without-border btn--size-medium btn--icon-position-right">
          {user?.isMfaEnabled ? t('mfa.action.enabled') : t('mfa.action.enable')}
        </button>
        {qrCode ? (
          <div>
            <img style={{ marginBottom: '2rem' }} src={qrCode} alt="" />
            <div className="login__inputWrap">
              <div className="field-type">
                <div className="field-type text read-only ">
                  <div className="input-wrapper">
                    <input
                      type="text"
                      placeholder={t('mfa.fields.keycode.placeholder')}
                      {...register('key', { required: true })}
                      required
                    />
                  </div>
                </div>
                <button
                  className="btn btn--style-primary btn--icon-style-without-border btn--size-medium"
                  onClick={() => handleKeyValidate()}
                  type="button">
                  {t('action.confirm')}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <></>
        )}
      </div>
    </form>
  );
}

export default MFAButton;
```

### Here is user service code

```
export class UserService {
  private API_URL = `/api/${ECollections.ADMIN_USERS}`;

  public async getQRCode() {
    const res = await fetch(`${this.API_URL}/qr`, {
      method: ERequestMethod.GET,
    });
    const data = await res.json();
    return data;
  }

  public async verifyQRCode(key: string) {
    const res = await fetch(`${this.API_URL}/qr/verify`, {
      method: ERequestMethod.POST,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ key }),
    });
    return await res.json();
  }

  public async checkMFAEnabled(payload: ILoginPayload) {
    const res = await fetch(`${this.API_URL}/login/check`, {
      method: ERequestMethod.POST,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    return await res.json();
  }

  public async getProfile() {
    const res = await fetch(`${this.API_URL}/me`);
    return await res.json();
  }
}
```

### Please use the custom component for login

```
export function Login() {
  const baseClass = 'login';
  const {
    register,
    watch,
    formState: { errors, isValid },
  } = useForm({
    mode: 'onChange',
  });

  const email = watch('email');
  const password = watch('password');
  const keycode = watch('keycode');

  const { t, i18n } = useTranslation('translation');
  const locale = useLocale();

  const [isShowKeycode, setIsShowKeyCode] = useState(false);

  const userService = new UserService();

  const checkIsMFAEnabled = async () => {
    try {
      const data = await userService.checkMFAEnabled({ email, password });
      setIsShowKeyCode(data?.isMfaEnabled);
      if (!data?.isMfaEnabled) {
        login();
      }
    } catch (error) {
      toast.error(error?.message ?? 'Something went wrong');
    }
  };

  const login = async () => {
    try {
      const result = await userService.login({ email, password, keycode });

      if (result?.token) {
        localStorage.setItem('token', result.token);
        window.location.href = '/';
        return result?.user;
      }

      if (result?.errors) {
        toast.error(result?.errors?.[0]?.message ?? 'Invalid Login');
      }
    } catch (e) {
      toast.error(e?.message ?? 'Something went wrong');
    }
  };

  const handleKeycodeButtonClick = (e: React.MouseEvent) => {
    e.preventDefault();
    checkIsMFAEnabled();
  };

  const handleKeyPressLogin = (event: any) => {
    if (event?.key === 'Enter') {
      if (isShowKeycode && isValid) {
        event.preventDefault();
        login();
      } else {
        if (isValid) {
          event.preventDefault();
          checkIsMFAEnabled();
        }
      }
    }
  };

  return (
    <div>
      <section className="login template-minimal template-minimal--width-normal">
        <div className="template-minimal__wrap">
          <form className="login__form form" onKeyDown={(e) => handleKeyPressLogin(e)}>
            {isShowKeycode ? (
              <div className="login__inputWrap">
                <div className="field-type email">
                  <label className="field-label" htmlFor="field-keycode">
                    {t('login.fields.keycode.label')}
                    <span className="required">*</span>
                  </label>
                  <div className="input-wrapper">
                    <input
                      id="field-keycode"
                      type="number"
                      {...register('keycode', {
                        required: true,
                      })}
                      className={errors?.keycode?.type === EFormValidationType.REQUIRED ? `${baseClass}__invalid` : ''}
                      placeholder={t('login.fields.keycode.placeholder')}
                    />
                    <p className="login__invalid">
                      {errors?.keycode?.type === EFormValidationType.REQUIRED ? (
                        <span>{t('validation.keycode.required')}</span>
                      ) : (
                        <></>
                      )}
                      <span className="hidden">hidden</span>
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="login__inputWrap">
                <div className="field-type email">
                  <label className="field-label" htmlFor="field-email">
                    {t('login.fields.email.label')}
                    <span className="required">*</span>
                  </label>
                  <div className="input-wrapper">
                    <input
                      autoComplete="email"
                      id="field-email"
                      type="email"
                      className={
                        errors?.email?.type === EFormValidationType.REQUIRED ||
                        errors?.email?.type === EFormValidationType.PATTERN
                          ? `${baseClass}__invalid`
                          : ''
                      }
                      placeholder={t('login.fields.email.placeholder')}
                      {...register('email', {
                        required: true,
                        pattern: EMAIL_REGEX,
                      })}
                    />
                    <p className="login__invalid">
                      {errors?.email?.type === EFormValidationType.REQUIRED ? (
                        <span>{t('validation.email.required')}</span>
                      ) : (
                        <></>
                      )}
                      {errors?.email?.type === EFormValidationType.PATTERN ? (
                        <span>{t('validation.email.invalid')}</span>
                      ) : (
                        <></>
                      )}
                      <span className="hidden">hidden</span>
                    </p>
                  </div>
                </div>
                <div className="field-type password">
                  <label className="field-label" htmlFor="field-password">
                    {t('login.fields.password.label')}
                    <span className="required">*</span>
                  </label>
                  <input
                    autoComplete="off"
                    id="field-password"
                    type="password"
                    className={
                      errors?.password?.type === EFormValidationType.REQUIRED ||
                      errors?.password?.type === EFormValidationType.PATTERN ||
                      errors?.password?.type === EFormValidationType.MIN_LENGTH
                        ? `${baseClass}__invalid`
                        : ''
                    }
                    placeholder={t('login.fields.password.placeholder')}
                    {...register('password', {
                      required: true,
                      pattern: PASSWORD_REGEX,
                      minLength: 10,
                    })}
                  />
                  <p className="login__invalid">
                    {errors?.password?.type === EFormValidationType.REQUIRED ? (
                      <span>{t('validation.password.required')}</span>
                    ) : (
                      <></>
                    )}
                    {errors?.password?.type === EFormValidationType.MIN_LENGTH ? (
                      <span>{t('validation.password.min_length')}</span>
                    ) : (
                      <></>
                    )}
                    {errors?.password?.type === EFormValidationType.PATTERN ? (
                      <span>{t('validation.password.pattern')}</span>
                    ) : (
                      <></>
                    )}
                    <span className="hidden">hidden</span>
                  </p>
                </div>
              </div>
            )}
            {!isShowKeycode && <Link to="/admin/forgot">{t('login.title.forgot_password')}?</Link>}
            <div className="form-submit">
              {isShowKeycode ? (
                <button
                  onClick={() => login()}
                  type="button"
                  className="btn btn--style-primary btn--icon-style-without-border btn--size-medium btn--icon-position-right">
                  <span className="btn__content">
                    <span className="btn__label">{t('action.confirm')}</span>
                  </span>
                </button>
              ) : (
                <button
                  disabled={!isValid}
                  onClick={(e) => handleKeycodeButtonClick(e)}
                  type="button"
                  className="btn btn--style-primary btn--icon-style-without-border btn--size-medium btn--icon-position-right">
                  <span className="btn__content">
                    <span className="btn__label">{t('login.action.login')}</span>
                  </span>
                </button>
              )}
            </div>
          </form>
        </div>
      </section>
    </div>
  );
}

export default Login;
```
