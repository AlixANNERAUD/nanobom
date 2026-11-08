//! Organization settings (members, upload tokens, webhook) and instance administration.

use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::hooks::use_params_map;

use crate::{
    components::{Empty, Heading, Loaded, Page, action, format_time, ui::*},
    functions::{
        AddMember, CreateToken, CreateUser, DeleteOrganization, DeleteWebhook, RemoveMember,
        RenameOrganization, ResetPassword, RevokeToken, SaveWebhook, SetMemberRole,
        SetUserAdministrator, SetUserDisabled, load_administration, load_settings,
    },
    model::{AdministrationData, Role, SettingsData, Severity},
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
                                                                "Role of " {member.username.clone()}
                                                            </label>
                                                            <select id=select_id name="role" class=format!("{SELECT} w-32")>
                                                                {role_options(member.manual_role, owners_allowed)}
                                                            </select>
                                                            <Button variant=ButtonVariant::Outline size=ButtonSize::Small>"Save"</Button>
                                                        </form>
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! {
                                                        <span>{member.manual_role.map_or("—", Role::label)}</span>
                                                    }
                                                        .into_any()
                                                }}
                                            </td>
                                            <td class=format!("{TABLE_CELL} text-muted-foreground")>
                                                {member.synchronized_role.map_or("—", Role::label)}
                                            </td>
                                            <td class=format!("{TABLE_CELL} text-right")>
                                                {(editable || member.user_id == current_user && member.manual_role.is_some())
                                                    .then(|| {
                                                        view! {
                                                            <form method="post" action={action::<RemoveMember>()}>
                                                                <input type="hidden" name="organization" value=organization.clone() />
                                                                <input type="hidden" name="user" value=user.clone() />
                                                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Small>
                                                                    {if member.user_id == current_user { "Leave" } else { "Remove" }}
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
                <CardTitle>"Members"</CardTitle>
                <CardDescription>
                    "Viewers read; members also ignore findings and start checks; admins also manage members, projects, tokens and the webhook; owners also manage owners. Roles from the identity provider's groups are shown apart and follow each sign-in."
                </CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-6">
                    <Table caption="Members and their roles">
                        <thead>
                            <tr class=TABLE_HEAD_ROW>
                                <th scope="col" class=TABLE_HEAD>"User"</th>
                                <th scope="col" class=TABLE_HEAD>"Role"</th>
                                <th scope="col" class=TABLE_HEAD>"From groups"</th>
                                <th scope="col" class=TABLE_HEAD>
                                    <span class="sr-only">"Actions"</span>
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
                            label="Add a user"
                            input_id="member-login"
                            hint="Username or email address of an existing account."
                        >
                            <input id="member-login" name="login" class=INPUT required />
                        </Field>
                        <Field label="Role" input_id="member-role">
                            <select id="member-role" name="role" class=SELECT>
                                {role_options(Some(Role::Viewer), owners_allowed)}
                            </select>
                        </Field>
                        <Button>"Add member"</Button>
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
                                                        {token.project_slug.clone().unwrap_or_else(|| "Whole organization".to_owned())}
                                                    </td>
                                                    <td class=format!("{TABLE_CELL} text-muted-foreground whitespace-nowrap")>
                                                        {token.last_used_at.map_or_else(|| "Never".to_owned(), format_time)}
                                                    </td>
                                                    <td class=format!("{TABLE_CELL} text-right")>
                                                        {if token.revoked {
                                                            view! { <Badge variant=BadgeVariant::Muted>"Revoked"</Badge> }.into_any()
                                                        } else {
                                                            view! {
                                                                <form method="post" action={action::<RevokeToken>()}>
                                                                    <input type="hidden" name="organization" value=organization />
                                                                    <input type="hidden" name="token" value=token.id.to_string() />
                                                                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small>"Revoke"</Button>
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
                <CardTitle>"Upload tokens"</CardTitle>
                <CardDescription>
                    "CI sends SBOMs with a token in the Authorization header. An organization token may also create projects; a project token only reaches its project."
                </CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-6">
                    {page
                        .new_token
                        .clone()
                        .map(|secret| {
                            view! {
                                <Alert variant=AlertVariant::Success title="Your new token">
                                    <p>"Copy it now and store it as a CI secret: it will not be shown again."</p>
                                    <label for="new-token" class="sr-only">"New token"</label>
                                    <input id="new-token" class=format!("{INPUT} mt-2 font-mono") readonly value=secret />
                                </Alert>
                            }
                        })}
                    {if !has_tokens {
                        view! { <Empty title="No token yet">"Create one below."</Empty> }.into_any()
                    } else {
                        view! {
                            <Table caption="Upload tokens">
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>"Name"</th>
                                        <th scope="col" class=TABLE_HEAD>"Scope"</th>
                                        <th scope="col" class=TABLE_HEAD>"Last used"</th>
                                        <th scope="col" class=TABLE_HEAD><span class="sr-only">"Actions"</span></th>
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
                        class="grid gap-4 sm:grid-cols-[2fr_1fr_auto] sm:items-end"
                    >
                        <input type="hidden" name="organization" value=organization.clone() />
                        <Field label="Token name" input_id="token-name">
                            <input id="token-name" name="name" class=INPUT required placeholder="GitHub Actions" />
                        </Field>
                        <Field label="Scope" input_id="token-project">
                            <select id="token-project" name="project" class=SELECT>
                                <option value="">"Whole organization"</option>
                                {page
                                    .projects
                                    .into_iter()
                                    .map(|project| view! { <option value=project.clone()>{project.clone()}</option> })
                                    .collect_view()}
                            </select>
                        </Field>
                        <Button>"Create token"</Button>
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
    let url = webhook
        .as_ref()
        .map(|webhook| webhook.url.clone())
        .unwrap_or_default();
    let last_delivery = webhook.as_ref().and_then(|webhook| {
        let status = webhook.last_delivery_status.clone().unwrap_or_default();
        webhook.last_delivery_at.map(|date| {
            view! {
                <p class="text-muted-foreground text-sm">
                    "Last delivery " {format_time(date)} ": " {status}
                </p>
            }
        })
    });
    let remove = webhook.is_some().then({
        let organization = organization.clone();
        move || {
            view! {
                <form method="post" action={action::<DeleteWebhook>()}>
                    <input type="hidden" name="organization" value=organization />
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Small>"Remove webhook"</Button>
                </form>
            }
        }
    });
    view! {
        <Card>
            <CardHeader>
                <CardTitle>"Webhook"</CardTitle>
                <CardDescription>
                    "After each check, new findings at or above the chosen severity are sent as one JSON document (documented in the README)."
                </CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-4">
                    {last_delivery}
                    <form method="post" action={action::<SaveWebhook>()} class="grid gap-4">
                        <input type="hidden" name="organization" value=organization.clone() />
                        <Field label="URL" input_id="webhook-url">
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
                            <Field label="Minimum severity" input_id="webhook-severity">
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
                                "Enabled"
                            </label>
                            <Button>"Save webhook"</Button>
                        </div>
                    </form>
                    {remove}
                </div>
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
                            <CardTitle>"Delete this organization"</CardTitle>
                            <CardDescription>
                                "Its projects, findings, tokens and memberships are deleted for good."
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <form
                                method="post"
                                action={action::<DeleteOrganization>()}
                                class="flex flex-wrap items-end gap-3"
                            >
                                <input type="hidden" name="organization" value=slug.clone() />
                                <Field label=format!("Type {slug} to confirm") input_id="delete-confirmation">
                                    <input id="delete-confirmation" name="confirmation" class=INPUT required autocomplete="off" />
                                </Field>
                                <Button variant=ButtonVariant::Destructive>"Delete organization"</Button>
                            </form>
                        </CardContent>
                    </Card>
                }
            }
        });
    view! {
        <Card>
            <CardHeader>
                <CardTitle>"Organization"</CardTitle>
            </CardHeader>
            <CardContent>
                <form
                    method="post"
                    action={action::<RenameOrganization>()}
                    class="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end"
                >
                    <input type="hidden" name="organization" value=slug.clone() />
                    <Field label="Name" input_id="organization-name">
                        <input id="organization-name" name="name" class=INPUT required value=organization.name.clone() />
                    </Field>
                    <Button variant=ButtonVariant::Secondary>"Rename"</Button>
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
        <Page title="Settings">
            <Loaded
                resource=page
                render={|page: SettingsData| {
                    let organization = page.organization.clone();
                    view! {
                        <Title text=format!("{} settings · nanobom", organization.name) />
                        <nav aria-label="Breadcrumb" class="text-muted-foreground text-sm">
                            <a class="hover:underline" href=format!("/organizations/{}", organization.slug)>
                                {organization.name.clone()}
                            </a>
                            " / "
                            <span aria-current="page">"Settings"</span>
                        </nav>
                        <Heading title="Settings" subtitle=organization.name.clone() />
                        <Members page=page.clone() />
                        <Tokens page=page.clone() />
                        <WebhookSettings page=page.clone() />
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
        <Page title="Administration">
            <Heading title="Administration" subtitle="Users and organizations of this instance." />
            <Loaded
                resource=page
                render={|page: AdministrationData| {
                    let current_user = page.current_user_id;
                    let minimum = page.password_minimum_length;
                    view! {
                        <Card>
                            <CardHeader>
                                <CardTitle>"Users"</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <Table caption="Users">
                                    <thead>
                                        <tr class=TABLE_HEAD_ROW>
                                            <th scope="col" class=TABLE_HEAD>"User"</th>
                                            <th scope="col" class=TABLE_HEAD>"Last sign-in"</th>
                                            <th scope="col" class=TABLE_HEAD>"Status"</th>
                                            <th scope="col" class=TABLE_HEAD><span class="sr-only">"Actions"</span></th>
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
                                                            {user.last_login_at.map_or_else(|| "Never".to_owned(), format_time)}
                                                        </td>
                                                        <td class=TABLE_CELL>
                                                            <div class="flex flex-wrap gap-1">
                                                                {user.is_instance_administrator.then(|| view! { <Badge>"Administrator"</Badge> })}
                                                                {user.is_disabled.then(|| view! { <Badge variant=BadgeVariant::Destructive>"Disabled"</Badge> })}
                                                                {(!user.has_password).then(|| view! { <Badge variant=BadgeVariant::Muted>"Single sign-on"</Badge> })}
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
                                                                                    {if user.is_disabled { "Enable" } else { "Disable" }}
                                                                                </Button>
                                                                            </form>
                                                                            <form method="post" action={action::<SetUserAdministrator>()}>
                                                                                <input type="hidden" name="user" value=id.clone() />
                                                                                <input type="hidden" name="administrator" value=(!user.is_instance_administrator).to_string() />
                                                                                <Button variant=ButtonVariant::Outline size=ButtonSize::Small>
                                                                                    {if user.is_instance_administrator { "Remove administrator" } else { "Make administrator" }}
                                                                                </Button>
                                                                            </form>
                                                                            {(page.local_accounts)
                                                                                .then(|| {
                                                                                    view! {
                                                                                        <form method="post" action={action::<ResetPassword>()} class="flex gap-2">
                                                                                            <input type="hidden" name="user" value=id.clone() />
                                                                                            <label for=password_id.clone() class="sr-only">
                                                                                                "New password for " {user.username.clone()}
                                                                                            </label>
                                                                                            <input
                                                                                                id=password_id.clone()
                                                                                                name="password"
                                                                                                type="password"
                                                                                                class=format!("{INPUT} h-8 w-40")
                                                                                                autocomplete="new-password"
                                                                                                minlength=minimum.to_string()
                                                                                                placeholder="New password"
                                                                                                required
                                                                                            />
                                                                                            <Button variant=ButtonVariant::Outline size=ButtonSize::Small>"Reset"</Button>
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
                                            <CardTitle>"New local account"</CardTitle>
                                        </CardHeader>
                                        <CardContent>
                                            <form method="post" action={action::<CreateUser>()} class="grid gap-4 sm:grid-cols-2">
                                                <Field label="Username" input_id="new-username">
                                                    <input id="new-username" name="username" class=INPUT required autocomplete="off" />
                                                </Field>
                                                <Field label="Email address (optional)" input_id="new-email">
                                                    <input id="new-email" name="email" type="email" class=INPUT autocomplete="off" />
                                                </Field>
                                                <Field
                                                    label="Password"
                                                    input_id="new-password"
                                                    hint=format!("At least {minimum} characters.")
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
                                                    "Instance administrator"
                                                </label>
                                                <div>
                                                    <Button>"Create user"</Button>
                                                </div>
                                            </form>
                                        </CardContent>
                                    </Card>
                                }
                            })}
                        <Card>
                            <CardHeader>
                                <CardTitle>"Organizations"</CardTitle>
                                <CardDescription>"Every organization of the instance; open one to manage it."</CardDescription>
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
                                                        " · " {organization.slug} {organization.is_personal.then_some(" · personal")}
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
