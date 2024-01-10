package de.mydomain.keycloak;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.actiontoken.updateemail.UpdateEmailActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.Templates;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.Urls;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.*;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;


public class MyRequiredAction implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(MyRequiredAction.class);

    public static final String PROVIDER_ID = "my_update_provider_id";

    private static final String EMAIL_FIELD = "email";

    /**
     * Wird jedes Mal aufgerufen, wenn sich ein Benutzer authentifiziert.
     * Dabei wird geprüft, ob die erforderliche Aktion ausgelöst werden soll.
     *
     * @param context
     */
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        /*
        if (context.getUser().getFirstAttribute(PHONE_NUMBER_FIELD) == null) {
            context.getUser().addRequiredAction(PROVIDER_ID);
            context.getAuthenticationSession().addRequiredAction(PROVIDER_ID);
        }
        */
    }

    /**
     * Wenn der Benutzer eine RequiredAction hat, wird diese Methode der erste Aufruf sein,
     * um zu erfahren, was dem Browser des Benutzers angezeigt werden soll.
     *
     * @param context
     */
    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.challenge(context.form().createResponse(UserModel.RequiredAction.UPDATE_EMAIL));
    }

    private Response createForm(RequiredActionContext requiredActionContext, Consumer<LoginFormsProvider> formConsumer) {

        LoginFormsProvider form = requiredActionContext.form();

        // für die Ausgabe des Usernames im Formular, z.B. "Hallo Maxmustermann"
        form.setAttribute("username", requiredActionContext.getUser().getUsername());

        // Wenn die User schon eine Telefonnummer hat, dann sie ist auch in der Maske entsprechend auszugeben
        String phoneNumber = requiredActionContext.getUser().getFirstAttribute(EMAIL_FIELD);
        form.setAttribute(EMAIL_FIELD, phoneNumber == null ? "" : phoneNumber);

        if (formConsumer != null) {
            formConsumer.accept(form);
        }

        return form.createForm("my_required_action_template.ftl");
    }

    /**
     * Wird aufgerufen, wenn eine RequiredAction Formulareingaben hat,
     * die man verarbeiten möchte.
     *
     * @param context
     */
    @Override
    public void processAction(RequiredActionContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String newEmail = formData.getFirst(UserModel.EMAIL);

        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        UserProfile emailUpdateValidationResult;
        try {
            emailUpdateValidationResult = validateEmailUpdate(context.getSession(), user, newEmail);
        } catch (ValidationException pve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());
            context.challenge(context.form().setErrors(errors).setFormData(formData).createResponse(UserModel.RequiredAction.UPDATE_EMAIL));
            return;
        }

        final boolean logoutSessions = "on".equals(formData.getFirst("logout-sessions"));
        if (!realm.isVerifyEmail() || Validation.isBlank(newEmail) || Objects.equals(user.getEmail(), newEmail) && user.isEmailVerified()) {
            if (logoutSessions) {
                AuthenticatorUtil.logoutOtherSessions(context);
            }
            updateEmailWithoutConfirmation(context, emailUpdateValidationResult);
            return;
        }

        sendEmailUpdateConfirmation(context, logoutSessions);

    }

    private void updateEmailWithoutConfirmation(RequiredActionContext context, UserProfile emailUpdateValidationResult) {

        updateEmailNow(context.getEvent(), context.getUser(), emailUpdateValidationResult);
        context.success();
    }

    public static void updateEmailNow(EventBuilder event, UserModel user, UserProfile emailUpdateValidationResult) {

        String oldEmail = user.getEmail();
        String newEmail = emailUpdateValidationResult.getAttributes().getFirstValue(UserModel.EMAIL);
        event.event(EventType.UPDATE_EMAIL).detail(Details.PREVIOUS_EMAIL, oldEmail).detail(Details.UPDATED_EMAIL, newEmail);
        emailUpdateValidationResult.update(false, new EventAuditingAttributeChangeListener(emailUpdateValidationResult, event));
    }

    public static UserProfile validateEmailUpdate(KeycloakSession session, UserModel user, String newEmail) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle(UserModel.USERNAME, user.getUsername());
        formData.putSingle(UserModel.EMAIL, newEmail);
        UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
        UserProfile profile = profileProvider.create(UserProfileContext.UPDATE_EMAIL, formData, user);
        profile.validate();
        return profile;
    }

    private void sendEmailUpdateConfirmation(RequiredActionContext context, boolean logoutSessions) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        UserModel user = context.getUser();

        String oldEmail = user.getEmail();
        String newEmail = formData.getFirst(UserModel.EMAIL);

        RealmModel realm = context.getRealm();

        int validityInSecs = realm.getActionTokenGeneratedByUserLifespan(UpdateEmailActionToken.TOKEN_TYPE);

        UriInfo uriInfo = context.getUriInfo();
        KeycloakSession session = context.getSession();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

        UpdateEmailActionToken actionToken = new UpdateEmailActionToken(user.getId(), Time.currentTime() + validityInSecs, oldEmail, newEmail, authenticationSession.getClient().getClientId(), logoutSessions);

        String link = Urls.actionTokenBuilder(uriInfo.getBaseUri(), actionToken.serialize(session, realm, uriInfo), authenticationSession.getClient().getClientId(), authenticationSession.getTabId()).build(realm.getName()).toString();

        context.getEvent().event(EventType.SEND_VERIFY_EMAIL).detail(Details.EMAIL, newEmail);
        try {
            session.getProvider(EmailTemplateProvider.class).setAuthenticationSession(authenticationSession).setRealm(realm).setUser(user).sendEmailUpdateConfirmation(link, TimeUnit.SECONDS.toMinutes(validityInSecs), newEmail);
        } catch (EmailException e) {
            logger.error("Failed to send email for email update", e);
            context.getEvent().error(Errors.EMAIL_SEND_FAILED);
            return;
        }
        context.getEvent().success();

        LoginFormsProvider forms = context.form();
        context.challenge(forms.setAttribute("messageHeader", forms.getMessage("emailUpdateConfirmationSentTitle")).setInfo("emailUpdateConfirmationSent", newEmail).createForm(Templates.getTemplate(LoginFormsPages.INFO)));
    }

    @Override
    public void close() {

    }

}
