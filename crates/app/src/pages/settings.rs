//! Organization settings (members, API tokens, webhook, license policy) and instance
//! administration.

use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::hooks::use_params_map;

use crate::{
    components::{Empty, Heading, Loaded, Page, action, format_time, ui::*},
    functions::{
        AddMember, CreateToken, CreateUser, DeleteOrganization, DeleteWebhook, RemoveMember,
        RenameOrganization, ResetPassword, RevokeToken, SaveLicensePolicy, SaveWebhook,
        SetMemberRole, SetUserAdministrator, SetUserDisabled, load_administration, load_settings,
    },
    model::{
        AdministrationData, DeliveryState, LicenseAction, Role, SettingsData, Severity,
        WebhookDelivery,
    },
    t, tf,
};

fn role_options(selected: Option<Role>, owners_allowed: bool) -> impl IntoView {
    Role::ALL
        .into_iter()
        .filter(move |role| owners_allowed || *role != Role::Owner)
        .map(move |role| {
            view! {
                <option value=role.as_str() selected=selected == Some(role)>
                    {role.label()}
                </option>
            }
        })
        .collect_view()
}

#[component]
fn Members(page: SettingsData) -> impl IntoView {
    let organization = page.organization.slug.clone();
    let owners_allowed = page.organization.role == Role::Owner;
    let current_user = page.current_user_id;
    let rows = page
                                .members
                                .into_iter()
                                .map(|member| {
                                    let organization = organization.clone();
                                    let user = member.user_id.to_string();
                                    let select_id = format!("member-role-{}", member.user_id);
                                    let editable = member.manual_role.is_some()
                                        && (owners_allowed || member.manual_role != Some(Role::Owner));
                                    view! {
                                        <tr class=TABLE_ROW>
                                            <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                                                {member.display_name.clone()}
                                                <span class="text-muted-foreground block text-xs font-normal">
                                                    {member.username.clone()}
                                                    {member.email.clone().map(|email| format!(" · {email}"))}
                                                </span>
                                            </th>
                                            <td class=TABLE_CELL>
                                                {if editable {
                                                    view! {
                                                        <form method="post" action={action::<SetMemberRole>()} class="flex gap-2">
                                                            <input type="hidden" name="organization" value=organization.clone() />
                                                            <input type="hidden" name="user" value=user.clone() />
                                                            <label for=select_id.clone() class="sr-only">
                                                                {tf!("settings.role_of", username = member.username.clone())}
                                                            </label>
                                                            <select id=select_id name="role" class=format!("{SELECT} w-32")>
                                                                {role_options(member.manual_role, owners_allowed)}
                                                            </select>
                                                            <Button variant=ButtonVariant::Outline size=ButtonSize::Small>{t!("settings.save")}</Button>
                                                        </form>
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! {
                                                        <span>{member.manual_role.map_or("-", Role::label)}</span>
                                                    }
                                                        .into_any()
                                                }}
                                            </td>
                                            <td class=format!("{TABLE_CELL} text-muted-foreground")>
                                                {member.synchronized_role.map_or("-", Role::label)}
                                            </td>
                                            <td class=format!("{TABLE_CELL} text-right")>
                                                {(editable || member.user_id == current_user && member.manual_role.is_some())
                                                    .then(|| {
                                                        view! {
                                                            <form method="post" action={action::<RemoveMember>()}>
                                                                <input type="hidden" name="organization" value=organization.clone() />
                                                                <input type="hidden" name="user" value=user.clone() />
                                                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small>
                                                                    {if member.user_id == current_user { t!("settings.leave") } else { t!("settings.remove") }}
                                                                </Button>
                                                            </form>
                                                        }
                                                    })}
                                            </td>
                                        </tr>
                                    }
                                })
                                .collect_view();
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("settings.members_title")}</CardTitle>
                <CardDescription>{t!("settings.members_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-6">
                    <Table caption=t!("settings.members_caption")>
                        <thead>
                            <tr class=TABLE_HEAD_ROW>
                                <th scope="col" class=TABLE_HEAD>{t!("settings.user")}</th>
                                <th scope="col" class=TABLE_HEAD>{t!("settings.role")}</th>
                                <th scope="col" class=TABLE_HEAD>{t!("settings.from_groups")}</th>
                                <th scope="col" class=TABLE_HEAD>
                                    <span class="sr-only">{t!("common.actions")}</span>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </Table>
                    <form
                        method="post"
                        action={action::<AddMember>()}
                        class="grid gap-4 sm:grid-cols-[2fr_1fr_auto] sm:items-end"
                    >
                        <input type="hidden" name="organization" value=organization.clone() />
                        <Field
                            label=t!("settings.add_user")
                            input_id="member-login"
                            hint=t!("settings.add_user_hint")
                        >
                            <input id="member-login" name="login" class=INPUT required />
                        </Field>
                        <Field label=t!("settings.role") input_id="member-role">
                            <select id="member-role" name="role" class=SELECT>
                                {role_options(Some(Role::Viewer), owners_allowed)}
                            </select>
                        </Field>
                        <Button>{t!("settings.add_member")}</Button>
                    </form>
                </div>
            </CardContent>
        </Card>
    }
}

#[component]
fn Tokens(page: SettingsData) -> impl IntoView {
    let organization = page.organization.slug.clone();
    let has_tokens = !page.tokens.is_empty();
    let rows = page
                                        .tokens
                                        .into_iter()
                                        .map(|token| {
                                            let organization = organization.clone();
                                            view! {
                                                <tr class=TABLE_ROW>
                                                    <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                                                        {token.name.clone()}
                                                        <span class="text-muted-foreground block font-mono text-xs font-normal">
                                                            {token.prefix.clone()} "…"
                                                        </span>
                                                    </th>
                                                    <td class=TABLE_CELL>
                                                        {token.project_slug.clone().unwrap_or_else(|| t!("settings.whole_organization").to_owned())}
                                                    </td>
                                                    <td class=TABLE_CELL>
                                                        {if token.read_only { t!("settings.scope_read") } else { t!("settings.scope_upload") }}
                                                    </td>
                                                    <td class=format!("{TABLE_CELL} text-muted-foreground whitespace-nowrap")>
                                                        {token.last_used_at.map_or_else(|| t!("common.never").to_owned(), format_time)}
                                                    </td>
                                                    <td class=format!("{TABLE_CELL} text-right")>
                                                        {if token.revoked {
                                                            view! { <Badge variant=BadgeVariant::Muted>{t!("settings.revoked")}</Badge> }.into_any()
                                                        } else {
                                                            view! {
                                                                <form method="post" action={action::<RevokeToken>()}>
                                                                    <input type="hidden" name="organization" value=organization />
                                                                    <input type="hidden" name="token" value=token.id.to_string() />
                                                                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small>{t!("settings.revoke")}</Button>
                                                                </form>
                                                            }
                                                                .into_any()
                                                        }}
                                                    </td>
                                                </tr>
                                            }
                                        })
                                        .collect_view();
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("settings.tokens_title")}</CardTitle>
                <CardDescription>{t!("settings.tokens_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-6">
                    {page
                        .new_token
                        .clone()
                        .map(|secret| {
                            view! {
                                <Alert variant=AlertVariant::Success title=t!("settings.new_token_title")>
                                    <p>{t!("settings.new_token_text")}</p>
                                    <label for="new-token" class="sr-only">{t!("settings.new_token_label")}</label>
                                    <input id="new-token" class=format!("{INPUT} mt-2 font-mono") readonly value=secret />
                                </Alert>
                            }
                        })}
                    {if !has_tokens {
                        view! { <Empty title=t!("settings.no_token_title")>{t!("settings.no_token_text")}</Empty> }.into_any()
                    } else {
                        view! {
                            <Table caption=t!("settings.tokens_title")>
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>{t!("settings.token_name_column")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("settings.token_project")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("settings.scope")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("settings.last_used")}</th>
                                        <th scope="col" class=TABLE_HEAD><span class="sr-only">{t!("common.actions")}</span></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows}
                                </tbody>
                            </Table>
                        }
                            .into_any()
                    }}
                    <form
                        method="post"
                        action={action::<CreateToken>()}
                        class="grid gap-4 sm:grid-cols-[2fr_1fr_1fr_auto] sm:items-end"
                    >
                        <input type="hidden" name="organization" value=organization.clone() />
                        <Field label=t!("settings.token_name") input_id="token-name">
                            <input id="token-name" name="name" class=INPUT required placeholder="GitHub Actions" />
                        </Field>
                        <Field label=t!("settings.token_project") input_id="token-project">
                            <select id="token-project" name="project" class=SELECT>
                                <option value="">{t!("settings.whole_organization")}</option>
                                {page
                                    .projects
                                    .into_iter()
                                    .map(|project| view! { <option value=project.clone()>{project.clone()}</option> })
                                    .collect_view()}
                            </select>
                        </Field>
                        <Field label=t!("settings.scope") input_id="token-scope">
                            <select id="token-scope" name="scope" class=SELECT>
                                <option value="upload">{t!("settings.scope_upload")}</option>
                                <option value="read">{t!("settings.scope_read")}</option>
                            </select>
                        </Field>
                        <Button>{t!("settings.create_token")}</Button>
                    </form>
                </div>
            </CardContent>
        </Card>
    }
}

#[component]
fn WebhookSettings(page: SettingsData) -> impl IntoView {
    let organization = page.organization.slug.clone();
    let webhook = page.webhook.clone();
    let minimum = webhook
        .as_ref()
        .map_or(Severity::High, |webhook| webhook.minimum_severity);
    let enabled = webhook.as_ref().is_none_or(|webhook| webhook.enabled);
    let exploited_only = webhook
        .as_ref()
        .is_some_and(|webhook| webhook.exploited_only);
    let format = webhook
        .as_ref()
        .map_or_else(|| "json".to_owned(), |webhook| webhook.format.clone());
    let url = webhook
        .as_ref()
        .map(|webhook| webhook.url.clone())
        .unwrap_or_default();
    let formats = [
        ("json", t!("settings.format_json")),
        ("slack", t!("settings.format_slack")),
        ("teams", t!("settings.format_teams")),
    ];
    let deliveries = (!page.deliveries.is_empty())
        .then(|| view! { <Deliveries deliveries=page.deliveries.clone() /> });
    let remove = webhook.is_some().then({
        let organization = organization.clone();
        move || {
            view! {
                <form method="post" action={action::<DeleteWebhook>()}>
                    <input type="hidden" name="organization" value=organization />
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small>{t!("settings.remove_webhook")}</Button>
                </form>
            }
        }
    });
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("settings.webhook_title")}</CardTitle>
                <CardDescription>{t!("settings.webhook_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-4">
                    <form method="post" action={action::<SaveWebhook>()} class="grid gap-4">
                        <input type="hidden" name="organization" value=organization.clone() />
                        <Field label=t!("settings.webhook_url") input_id="webhook-url">
                            <input
                                id="webhook-url"
                                name="url"
                                type="url"
                                class=INPUT
                                required
                                value=url
                                placeholder="https://homeassistant.example.org/api/webhook/nanobom"
                            />
                        </Field>
                        <div class="flex flex-wrap items-end gap-4">
                            <Field label=t!("settings.webhook_format") input_id="webhook-format">
                                <select id="webhook-format" name="format" class=format!("{SELECT} w-64")>
                                    {formats
                                        .into_iter()
                                        .map(|(value, label)| {
                                            view! { <option value=value selected=value == format>{label}</option> }
                                        })
                                        .collect_view()}
                                </select>
                            </Field>
                            <Field label=t!("settings.minimum_severity") input_id="webhook-severity">
                                <select id="webhook-severity" name="minimum_severity" class=format!("{SELECT} w-40")>
                                    {Severity::DESCENDING
                                        .into_iter()
                                        .map(|severity| {
                                            view! {
                                                <option value=severity.as_str() selected=severity == minimum>
                                                    {severity.label()}
                                                </option>
                                            }
                                        })
                                        .collect_view()}
                                </select>
                            </Field>
                            <label class=format!("{LABEL} h-9")>
                                <input type="checkbox" name="enabled" class=CHECKBOX checked=enabled />
                                {t!("settings.enabled")}
                            </label>
                            <label class=format!("{LABEL} h-9")>
                                <input type="checkbox" name="exploited_only" class=CHECKBOX checked=exploited_only />
                                {t!("settings.exploited_only")}
                            </label>
                            <Button>{t!("settings.save_webhook")}</Button>
                        </div>
                    </form>
                    {remove}
                    {deliveries}
                </div>
            </CardContent>
        </Card>
    }
}

/// The latest deliveries to the webhook: their state, attempts and the last answer.
#[component]
fn Deliveries(deliveries: Vec<WebhookDelivery>) -> impl IntoView {
    let rows = deliveries
        .into_iter()
        .map(|delivery| {
            let variant = match delivery.state {
                DeliveryState::Delivered => BadgeVariant::Secondary,
                DeliveryState::Sending | DeliveryState::Pending | DeliveryState::Cancelled => {
                    BadgeVariant::Outline
                }
                DeliveryState::Failed => BadgeVariant::Destructive,
            };
            let last_attempt = delivery.last_attempt_at.map_or_else(
                || t!("common.never").to_owned(),
                |time| match &delivery.last_status {
                    Some(status) => format!("{} · {status}", format_time(time)),
                    None => format_time(time),
                },
            );
            // A delivery being sent holds a lease, not a scheduled attempt: no time to show.
            let next_attempt = (delivery.state == DeliveryState::Pending)
                .then_some(delivery.next_attempt_at)
                .flatten()
                .map(|time| {
                    view! {
                        <span class="text-muted-foreground block text-xs">
                            {tf!("settings.delivery_next_attempt", time = format_time(time))}
                        </span>
                    }
                });
            view! {
                <tr class=TABLE_ROW>
                    <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                        <span class="font-mono text-xs">{delivery.event.clone()}</span>
                        <span class="text-muted-foreground block text-xs font-normal">
                            {format_time(delivery.created_at)}
                        </span>
                    </th>
                    <td class=TABLE_CELL>
                        <Badge variant=variant>{delivery.state.label()}</Badge>
                        {next_attempt}
                    </td>
                    <td class=format!("{TABLE_CELL} tabular-nums")>{delivery.attempts}</td>
                    <td class=format!("{TABLE_CELL} text-muted-foreground")>{last_attempt}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <section class="grid gap-2">
            <h3 class="text-sm font-medium">{t!("settings.deliveries_title")}</h3>
            <Table caption=t!("settings.deliveries_title")>
                <thead>
                    <tr class=TABLE_HEAD_ROW>
                        <th scope="col" class=TABLE_HEAD>{t!("settings.delivery_event")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("settings.delivery_state")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("settings.delivery_attempts")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("settings.delivery_last_attempt")}</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </Table>
        </section>
    }
}

/// The license policy: three lists of identifiers, replaced as a whole on save, and the two
/// defaults.
#[component]
fn LicensePolicySettings(page: SettingsData) -> impl IntoView {
    let organization = page.organization.slug.clone();
    let policy = page.license_policy;
    let select = |id: &'static str, name: &'static str, selected: LicenseAction| {
        view! {
            <select id=id name=name class=format!("{SELECT} w-40")>
                {LicenseAction::ALL
                    .into_iter()
                    .map(|action| {
                        view! {
                            <option value=action.as_str() selected=action == selected>
                                {action.label()}
                            </option>
                        }
                    })
                    .collect_view()}
            </select>
        }
    };
    let lists = [
        (
            "license-allowed",
            "allowed",
            t!("settings.licenses_allowed"),
            "MIT\nApache-2.0",
            policy.allowed,
        ),
        (
            "license-warned",
            "warned",
            t!("settings.licenses_warned"),
            "MPL-2.0",
            policy.warned,
        ),
        (
            "license-forbidden",
            "forbidden",
            t!("settings.licenses_forbidden"),
            "AGPL-3.0-only",
            policy.forbidden,
        ),
    ]
    .into_iter()
    .map(|(id, name, label, placeholder, licenses)| {
        view! {
            <Field label input_id=id>
                <textarea
                    id=id
                    name=name
                    class=format!("{TEXTAREA} font-mono")
                    rows="5"
                    spellcheck="false"
                    autocomplete="off"
                    placeholder=placeholder
                >
                    {licenses.join("\n")}
                </textarea>
            </Field>
        }
    })
    .collect_view();
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("settings.licenses_title")}</CardTitle>
                <CardDescription>{t!("settings.licenses_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <form method="post" action={action::<SaveLicensePolicy>()} class="grid gap-4">
                    <input type="hidden" name="organization" value=organization />
                    <div class="grid gap-4 md:grid-cols-3">{lists}</div>
                    <p class="text-muted-foreground text-sm">{t!("settings.licenses_hint")}</p>
                    <div class="flex flex-wrap items-end gap-4">
                        <Field label=t!("settings.licenses_unlisted") input_id="license-unlisted">
                            {select("license-unlisted", "unlisted", policy.unlisted)}
                        </Field>
                        <Field label=t!("settings.licenses_unknown") input_id="license-unknown">
                            {select("license-unknown", "unknown", policy.unknown)}
                        </Field>
                        <Button>{t!("settings.save_license_policy")}</Button>
                    </div>
                </form>
            </CardContent>
        </Card>
    }
}

#[component]
fn OrganizationSettings(page: SettingsData) -> impl IntoView {
    let organization = page.organization.clone();
    let slug = organization.slug.clone();
    let delete = (organization.role == Role::Owner).then({
            let slug = slug.clone();
            move || {
                view! {
                    <Card class="border-destructive/40">
                        <CardHeader>
                            <CardTitle>{t!("settings.delete_title")}</CardTitle>
                            <CardDescription>{t!("settings.delete_description")}</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <form
                                method="post"
                                action={action::<DeleteOrganization>()}
                                class="flex flex-wrap items-end gap-3"
                            >
                                <input type="hidden" name="organization" value=slug.clone() />
                                <Field label=tf!("common.type_to_confirm", slug = slug.clone()) input_id="delete-confirmation">
                                    <input id="delete-confirmation" name="confirmation" class=INPUT required autocomplete="off" />
                                </Field>
                                <Button variant=ButtonVariant::Destructive>{t!("settings.delete")}</Button>
                            </form>
                        </CardContent>
                    </Card>
                }
            }
        });
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("settings.organization_title")}</CardTitle>
            </CardHeader>
            <CardContent>
                <form
                    method="post"
                    action={action::<RenameOrganization>()}
                    class="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end"
                >
                    <input type="hidden" name="organization" value=slug.clone() />
                    <Field label=t!("settings.organization_name") input_id="organization-name">
                        <input id="organization-name" name="name" class=INPUT required value=organization.name.clone() />
                    </Field>
                    <Button variant=ButtonVariant::Secondary>{t!("settings.rename")}</Button>
                </form>
            </CardContent>
        </Card>
        {delete}
    }
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.read().get("organization").unwrap_or_default();
    let page = Resource::new(slug, load_settings);
    view! {
        <Page title=t!("settings.title")>
            <Loaded
                resource=page
                render={|page: SettingsData| {
                    let organization = page.organization.clone();
                    view! {
                        <Title text=format!("{} · nanobom", tf!("settings.page_title", name = organization.name.clone())) />
                        <nav aria-label=t!("common.breadcrumb") class="text-muted-foreground text-sm">
                            <a class="hover:underline" href=format!("/organizations/{}", organization.slug)>
                                {organization.name.clone()}
                            </a>
                            " / "
                            <span aria-current="page">{t!("settings.title")}</span>
                        </nav>
                        <Heading title=t!("settings.title") subtitle=organization.name.clone() />
                        <Members page=page.clone() />
                        <Tokens page=page.clone() />
                        <WebhookSettings page=page.clone() />
                        <LicensePolicySettings page=page.clone() />
                        <OrganizationSettings page />
                    }
                }}
            />
        </Page>
    }
}

#[component]
pub fn AdministrationPage() -> impl IntoView {
    let page = Resource::new(|| (), |()| load_administration());
    view! {
        <Page title=t!("administration.title")>
            <Heading title=t!("administration.title") subtitle=t!("administration.subtitle") />
            <Loaded
                resource=page
                render={|page: AdministrationData| {
                    let current_user = page.current_user_id;
                    let minimum = page.password_minimum_length;
                    view! {
                        <Card>
                            <CardHeader>
                                <CardTitle>{t!("administration.users")}</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <Table caption=t!("administration.users")>
                                    <thead>
                                        <tr class=TABLE_HEAD_ROW>
                                            <th scope="col" class=TABLE_HEAD>{t!("administration.user")}</th>
                                            <th scope="col" class=TABLE_HEAD>{t!("administration.last_sign_in")}</th>
                                            <th scope="col" class=TABLE_HEAD>{t!("administration.status")}</th>
                                            <th scope="col" class=TABLE_HEAD><span class="sr-only">{t!("common.actions")}</span></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {page
                                            .users
                                            .into_iter()
                                            .map(|user| {
                                                let id = user.id.to_string();
                                                let password_id = format!("password-{}", user.id);
                                                let myself = user.id == current_user;
                                                view! {
                                                    <tr class=TABLE_ROW>
                                                        <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                                                            {user.display_name.clone()}
                                                            <span class="text-muted-foreground block text-xs font-normal">
                                                                {user.username.clone()}
                                                                {user.email.clone().map(|email| format!(" · {email}"))}
                                                            </span>
                                                        </th>
                                                        <td class=format!("{TABLE_CELL} text-muted-foreground whitespace-nowrap")>
                                                            {user.last_login_at.map_or_else(|| t!("common.never").to_owned(), format_time)}
                                                        </td>
                                                        <td class=TABLE_CELL>
                                                            <div class="flex flex-wrap gap-1">
                                                                {user.is_instance_administrator.then(|| view! { <Badge>{t!("administration.administrator")}</Badge> })}
                                                                {user.is_disabled.then(|| view! { <Badge variant=BadgeVariant::Destructive>{t!("administration.disabled")}</Badge> })}
                                                                {(!user.has_password).then(|| view! { <Badge variant=BadgeVariant::Muted>{t!("administration.single_sign_on")}</Badge> })}
                                                            </div>
                                                        </td>
                                                        <td class=TABLE_CELL>
                                                            {(!myself)
                                                                .then(|| {
                                                                    view! {
                                                                        <div class="flex flex-wrap justify-end gap-2">
                                                                            <form method="post" action={action::<SetUserDisabled>()}>
                                                                                <input type="hidden" name="user" value=id.clone() />
                                                                                <input type="hidden" name="disabled" value=(!user.is_disabled).to_string() />
                                                                                <Button variant=ButtonVariant::Outline size=ButtonSize::Small>
                                                                                    {if user.is_disabled { t!("administration.enable") } else { t!("administration.disable") }}
                                                                                </Button>
                                                                            </form>
                                                                            <form method="post" action={action::<SetUserAdministrator>()}>
                                                                                <input type="hidden" name="user" value=id.clone() />
                                                                                <input type="hidden" name="administrator" value=(!user.is_instance_administrator).to_string() />
                                                                                <Button variant=ButtonVariant::Outline size=ButtonSize::Small>
                                                                                    {if user.is_instance_administrator {
                                                                                        t!("administration.remove_administrator")
                                                                                    } else {
                                                                                        t!("administration.make_administrator")
                                                                                    }}
                                                                                </Button>
                                                                            </form>
                                                                            {(page.local_accounts)
                                                                                .then(|| {
                                                                                    view! {
                                                                                        <form method="post" action={action::<ResetPassword>()} class="flex gap-2">
                                                                                            <input type="hidden" name="user" value=id.clone() />
                                                                                            <label for=password_id.clone() class="sr-only">
                                                                                                {tf!("administration.new_password_for", username = user.username.clone())}
                                                                                            </label>
                                                                                            <input
                                                                                                id=password_id.clone()
                                                                                                name="password"
                                                                                                type="password"
                                                                                                class=format!("{INPUT} h-8 w-40")
                                                                                                autocomplete="new-password"
                                                                                                minlength=minimum.to_string()
                                                                                                placeholder=t!("administration.new_password")
                                                                                                required
                                                                                            />
                                                                                            <Button variant=ButtonVariant::Outline size=ButtonSize::Small>{t!("administration.reset")}</Button>
                                                                                        </form>
                                                                                    }
                                                                                })}
                                                                        </div>
                                                                    }
                                                                })}
                                                        </td>
                                                    </tr>
                                                }
                                            })
                                            .collect_view()}
                                    </tbody>
                                </Table>
                            </CardContent>
                        </Card>
                        {page
                            .local_accounts
                            .then(|| {
                                view! {
                                    <Card>
                                        <CardHeader>
                                            <CardTitle>{t!("administration.new_account")}</CardTitle>
                                        </CardHeader>
                                        <CardContent>
                                            <form method="post" action={action::<CreateUser>()} class="grid gap-4 sm:grid-cols-2">
                                                <Field label=t!("administration.username") input_id="new-username">
                                                    <input id="new-username" name="username" class=INPUT required autocomplete="off" />
                                                </Field>
                                                <Field label=t!("administration.email") input_id="new-email">
                                                    <input id="new-email" name="email" type="email" class=INPUT autocomplete="off" />
                                                </Field>
                                                <Field
                                                    label=t!("administration.password")
                                                    input_id="new-password"
                                                    hint=tf!("administration.password_hint", minimum = minimum)
                                                >
                                                    <input
                                                        id="new-password"
                                                        name="password"
                                                        type="password"
                                                        class=INPUT
                                                        required
                                                        minlength=minimum.to_string()
                                                        autocomplete="new-password"
                                                    />
                                                </Field>
                                                <label class=format!("{LABEL} self-end h-9")>
                                                    <input type="checkbox" name="administrator" class=CHECKBOX />
                                                    {t!("administration.instance_administrator")}
                                                </label>
                                                <div>
                                                    <Button>{t!("administration.create_user")}</Button>
                                                </div>
                                            </form>
                                        </CardContent>
                                    </Card>
                                }
                            })}
                        <Card>
                            <CardHeader>
                                <CardTitle>{t!("administration.organizations")}</CardTitle>
                                <CardDescription>{t!("administration.organizations_description")}</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <ul class="grid gap-2 text-sm">
                                    {page
                                        .organizations
                                        .into_iter()
                                        .map(|organization| {
                                            view! {
                                                <li>
                                                    <a class="font-medium underline-offset-4 hover:underline" href=format!("/organizations/{}/settings", organization.slug)>
                                                        {organization.name}
                                                    </a>
                                                    <span class="text-muted-foreground">
                                                        " · " {organization.slug} {organization.is_personal.then(|| format!(" · {}", t!("common.personal")))}
                                                    </span>
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            </CardContent>
                        </Card>
                    }
                }}
            />
        </Page>
    }
}
