package com.myeeshen.xposed.mods.xgmailmarkasread;

import static de.robv.android.xposed.XposedHelpers.callMethod;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.findClass;
import static de.robv.android.xposed.XposedHelpers.getBooleanField;
import static de.robv.android.xposed.XposedHelpers.getLongField;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.newInstance;
import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.IXposedHookInitPackageResources;
import de.robv.android.xposed.callbacks.XC_InitPackageResources.InitPackageResourcesParam;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Parcel;
import android.annotation.SuppressLint;
import android.app.PendingIntent;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class XGmailMarkAsRead implements IXposedHookInitPackageResources,
		IXposedHookLoadPackage {
	static final String PKG_GMAIL = "com.google.android.gm";
	static final String PKG_AMAIL = "com.android.mail";
	static final String PKG_AMAIL_PROVIDERS = PKG_AMAIL + ".providers";
	static final String PKG_AMAIL_UTILS = PKG_AMAIL + ".utils";
	static final String PKG_AMAIL_ACTION = PKG_AMAIL + ".action";
	static final String NAIS = PKG_AMAIL + ".NotificationActionIntentService";
	static final String MIS = PKG_AMAIL + ".MailIntentService";
	static final String PROVIDERS_ACCOUNT = PKG_AMAIL_PROVIDERS + ".Account";
	static final String PROVIDERS_FOLDER = PKG_AMAIL_PROVIDERS + ".Folder";
	static final String UTILS_NU = PKG_AMAIL_UTILS + ".NotificationUtils";
	static final String UTILS_NAU = PKG_AMAIL_UTILS
			+ ".NotificationActionUtils";
	static final String UTILS_NAU_NA = UTILS_NAU + "$NotificationAction";
	static final String UTILS_NAU_NAT = UTILS_NAU + "$NotificationActionType";

	static final String ACTION_MARK_READ = PKG_AMAIL_ACTION
			+ ".notification.MARK_READ";
	static final String ACTION_RESEND_NOTIFICATIONS = PKG_AMAIL_ACTION
			+ ".RESEND_NOTIFICATIONS";

	static final String A_ENA = PKG_AMAIL + ".extra.EXTRA_NOTIFICATION_ACTION";
	static int actionIconId = -1;
	static int actionStrId = -1;

	@Override
	public void handleLoadPackage(final LoadPackageParam lpparam)
			throws Throwable {
		if (lpparam.packageName.equals(PKG_GMAIL)) {
			hookGmail(lpparam);
		}
	}

	@Override
	public void handleInitPackageResources(InitPackageResourcesParam resparam)
			throws Throwable {
		if (resparam.packageName.equals(PKG_GMAIL)) {
			actionIconId = resparam.res.getIdentifier(
					"ic_menu_inbox_main_holo_dark", "drawable", PKG_GMAIL);
			// Some string that is ignored
			actionStrId = resparam.res.getIdentifier(
					"notification_action_archive", "string", PKG_GMAIL);
		}
	}

	public static class HookAddNotificationAction {
		private Class<?> na_utils;
		private Class<?> na_utils_na;
		private Class<?> na_utils_nat;

		private Object nat_read = null;
		private String actionStr = "Read";

		public HookAddNotificationAction(ClassLoader classLoader) {
			na_utils = findClass(UTILS_NAU, classLoader);
			na_utils_na = findClass(UTILS_NAU_NA, classLoader);
			na_utils_nat = findClass(UTILS_NAU_NAT, classLoader);

			// Create a NotificationActionType for READ.
			// 0 must be inside the number of enums for NAT (currently 4)
			// Don't think it has any effect what integer it is.
			// true indicates destructive action in an effort to get the
			// notification to resend
			nat_read = newInstance(na_utils_nat, "READ", 0, "read", true,
					actionIconId, actionStrId);
			try {
				XposedBridge.hookMethod(
						findMethodAddNotificationActions(na_utils),
						hookPendingIntent);
			} catch (NoSuchMethodError exc) {
				log("unable to hook addNotificationActions");
			}
		}

		private String findFieldNameMessageServerId(Object message) {
			// aKe = "serverId"
			// deduced that aKe = read in android.mail.providers.Message
			// not sure how to get it automatically
			return "aKe";
		}

		private String findFieldNameRead(Object message) {
			// guessing that In = read in android.mail.providers.Message
			// it's either that or aKt
			// UIProvider.MESSAGE_READ_COLUMN = 22
			// not sure how to get it automatically
			return "In";
		}

		private Method findMethodAddNotificationActions(Class<?> na_utils) {
			// public static void a(Context paramContext, Intent
			// paramIntent, f paramf, a parama, Account paramAccount,
			// Conversation paramConversation, Message paramMessage, Folder
			// paramFolder, int paramInt, long paramLong, Set<String>
			// paramSet)
			// a = addNotificationActions
			Method found = null;
			for (final Method mmm : na_utils.getDeclaredMethods()) {
				final int modifiers = mmm.getModifiers();
				if (!Modifier.isPublic(modifiers)
						|| !Modifier.isStatic(modifiers)
						|| !mmm.getReturnType().equals(Void.TYPE)) {
					continue;
				}
				Class<?>[] ptypes = mmm.getParameterTypes();
				if (ptypes.length <= 2 || !ptypes[0].equals(Context.class)
						|| !ptypes[1].equals(Intent.class)) {
					continue;
				}
				if (found == null) {
					found = mmm;
				} else {
					log("Error found multiple ANA");
				}
			}
			if (found == null) {
				log("Error did not find ANA");
			}
			return found;
		}

		private String findMethodNamePutNotificationActionExtra(
				Class<?> na_utils) {
			// private static void a(Intent paramIntent,
			// NotificationActionUtils.NotificationAction
			// paramNotificationAction)
			// a = putNotificationActionExtra
			Method found = null;
			for (final Method mmm : na_utils.getDeclaredMethods()) {
				final int modifiers = mmm.getModifiers();
				if (!Modifier.isPrivate(modifiers)
						|| !Modifier.isStatic(modifiers)
						|| !mmm.getReturnType().equals(Void.TYPE)) {
					continue;
				}
				Class<?>[] ptypes = mmm.getParameterTypes();
				if (ptypes.length <= 1 || !ptypes[0].equals(Intent.class)) {
					continue;
				}

				if (found == null) {
					found = mmm;
				} else {
					log("Error found multiple PNAE");
				}
			}
			if (found == null) {
				log("Error did not find PNAE");
				return "";
			}
			return found.getName();
		}

		private String findMethodNameAddAction(Object notification) {
			// public Builder addAction(int icon, CharSequence title,
			// PendingIntent intent)
			// b = addAction
			Method found = null;
			for (final Method mmm : notification.getClass()
					.getDeclaredMethods()) {
				final int modifiers = mmm.getModifiers();
				if (!Modifier.isPublic(modifiers)) {
					continue;
				}
				Class<?>[] ptypes = mmm.getParameterTypes();
				if (ptypes.length < 3 || !ptypes[0].equals(int.class)
						|| !ptypes[1].equals(CharSequence.class)
						|| !ptypes[2].equals(PendingIntent.class)) {
					continue;
				}
				if (found == null) {
					found = mmm;
				} else {
					log("Error found multiple AA");
				}
			}
			if (found == null) {
				log("Error did not find AA");
				return "";
			}
			return found.getName();
		}

		XC_MethodHook hookPendingIntent = new XC_MethodHook() {
			@Override
			/** Attempt to add a notification action for mark read
			 *
			 */
			protected void beforeHookedMethod(MethodHookParam param)
					throws Throwable {
				// addNotificationActions(
				// 0 final Context context,
				// 1 final Intent notificationIntent,
				// 2 final NotificationCompat.Builder notification,
				// 3 final Account account,
				// 4 final Conversation conversation,
				// 5 final Message message,
				// 6 final Folder folder,
				// 7 final int notificationId,
				// 8 final long when,
				// 9 final Set<String> notificationActions)

				final Context context = (Context) param.args[0];
				final Object notification = param.args[2];
				final Object account = param.args[4];
				final Object conversation = param.args[5];
				final Object message = param.args[6];
				final Object folder = param.args[7];
				final long conversation_id = getLongField(conversation, "id");
				final String msg_server_id = (String) getObjectField(message,
						findFieldNameMessageServerId(message));
				final long msg_id = getLongField(message, "id");
				final int notificationId = (int) param.args[8];
				final long when = (long) param.args[9];

				final boolean msgRead = getBooleanField(message,
						findFieldNameRead(message));

				log("is read? " + msg_server_id + " " + msg_id + " " + msgRead);
				if (msgRead) {
					log("message is read, not adding read action");
					return;
				}
				addNotificationAction(context, notificationId, notification,
						account, conversation, message, folder,
						conversation_id, msg_server_id, msg_id, when);
			}
		};

		public void addNotificationAction(Context context, int notificationId,
				Object notification, Object account, Object conversation,
				Object message, Object folder, long conversation_id,
				String msg_server_id, long msg_id, long when) {

			// new NotificationAction(
			// 0 notificationActionType,
			// 1 account,
			// 2 conversation,
			// 3 message,
			// 4 folder,
			// 5 conversation.id,
			// 6 message.serverId,
			// 7 message.id,
			// 8 when);
			final Object notificationAction = newInstance(na_utils_na,
					nat_read, account, conversation, message, folder,
					conversation_id, msg_server_id, msg_id, when);

			// ACTION_MARK_READ has been compiled in. Must redefine.
			final String intentAction = ACTION_MARK_READ;
			final Intent intent = new Intent(intentAction);
			intent.setPackage(context.getPackageName());

			callStaticMethod(na_utils,
					findMethodNamePutNotificationActionExtra(na_utils), intent,
					notificationAction);

			final PendingIntent pendingIntent = PendingIntent.getService(
					context, notificationId, intent,
					PendingIntent.FLAG_UPDATE_CURRENT);

			callMethod(notification, findMethodNameAddAction(notification),
					actionIconId, actionStr, pendingIntent);

			log("added read action");
		}

		private void log(String logmsg) {
			XposedBridge.log("XGMAR.addNA:" + logmsg);
		}
	}

	private static void log(String logmsg) {
		XposedBridge.log("XGMAR:" + logmsg);
	}

	@SuppressLint("Recycle")
	private static void logIntentExtra(Intent intent, ClassLoader classLoader) {
		final byte[] data = intent.getByteArrayExtra(A_ENA);

		if (data != null) {
			final Parcel in = Parcel.obtain();
			in.unmarshall(data, 0, data.length);
			in.setDataPosition(0);

			log("parcel:NAT   :" + in.readInt());
			final Object account = in.readParcelable(classLoader);
			log("parcel:acct  :" + account);
			log("parcel:conv  :" + in.readParcelable(classLoader));
			log("parcel:mesg  :" + in.readParcelable(classLoader));
			final Object folder = in.readParcelable(classLoader);
			log("parcel:fold  :" + folder);
			log("parcel:convid:" + in.readLong());
			log("parcel:mesgid:" + in.readString());
			log("parcel:lmsgid:" + in.readLong());
			log("parcel:when  :" + in.readLong());

		} else {
			log("data was null trying to unparcel the NotificationAction");
		}
	}

	public static class HookOnHandleIntent {
		private Class<?> na_utils;
		private Class<?> na_utils_na;
		private Class<?> mis;
		private Class<?> nu;
		private Class<?> folderUriClass;
		private Method nauRN;
		private Method nuRN;

		public HookOnHandleIntent(ClassLoader classLoader) {
			na_utils = findClass(UTILS_NAU, classLoader);
			na_utils_na = findClass(UTILS_NAU_NA, classLoader);
			// MailIntentService = h
			mis = findClass(PKG_AMAIL + ".h", classLoader);
			// NotificationUtils = s (guess)
			nu = findClass(PKG_AMAIL_UTILS + ".s", classLoader);
			// com.android.mail.utils.FolderUri = k
			folderUriClass = findClass(PKG_AMAIL_UTILS + ".k", classLoader);

			nauRN = findMethodNAURN();
			nuRN = findMethodNURN();

			try {
				findAndHookMethod(NAIS, classLoader, "onHandleIntent",
						Intent.class, hookNAIS);
			} catch (NoSuchMethodError exc) {
				log("unable to hook nais.onHandleIntent");
			}
			try {
				findAndHookMethod(mis, "onHandleIntent", Intent.class, hookMIS);
			} catch (NoSuchMethodError exc) {
				log("unable to hook mis.onHandleIntent");
			}
		}

		XC_MethodHook hookNAIS = new XC_MethodHook() {
			@SuppressLint("Recycle")
			@Override
			protected void afterHookedMethod(MethodHookParam param)
					throws Throwable {
				final Intent intent = (Intent) param.args[0];
				// final ClassLoader classLoader = (ClassLoader) callMethod(
				// na_utils_na, "getClassLoader");
				// logIntentExtra(intent, classLoader);

				if (intent.getAction().equals(ACTION_MARK_READ)) {
					log("after mark read, resending notifications");

					final ClassLoader classLoader = (ClassLoader) callMethod(
							na_utils_na, "getClassLoader");
					final byte[] data = intent.getByteArrayExtra(A_ENA);

					if (data != null) {
						final Parcel in = Parcel.obtain();
						in.unmarshall(data, 0, data.length);
						in.setDataPosition(0);

						in.readInt();
						final Object account = in.readParcelable(classLoader);
						in.readParcelable(classLoader);
						in.readParcelable(classLoader);
						final Object folder = in.readParcelable(classLoader);

						nauRN.invoke(null, param.thisObject, account, folder);
					} else {
						log("data was null trying to unparcel the NotificationAction");
					}
				}
			}
		};

		XC_MethodHook hookMIS = new XC_MethodHook() {
			@Override
			// Not sure why this is necessary for notifications to be resent.
			// There seems to be a call to
			// NotificationUtils.resendNotifications inside
			// MailIntentService.onHandleIntent that should already do the
			// trick.
			// Is there a bit of a race? Whether the mark read reaches Gmail
			// first or the resend?
			protected void beforeHookedMethod(MethodHookParam param)
					throws Throwable {
				final Intent intent = (Intent) param.args[0];
				if (!intent.getAction().equals(ACTION_RESEND_NOTIFICATIONS)) {
					return;
				}
				log("MIS:resending notifications");

				Uri accountUri = intent.getParcelableExtra("accountUri");
				Uri folderUri = intent.getParcelableExtra("folderUri");
				Object fu = newInstance(folderUriClass, folderUri);

				nuRN.invoke(null, param.thisObject, false, accountUri, fu);
			}
		};

		// NotificationUtils.resendNotifications
		private Method findMethodNURN() {
			Method found = null;
			for (Method mmm : nu.getDeclaredMethods()) {
				final int modifiers = mmm.getModifiers();
				if (!Modifier.isPublic(modifiers)
						|| !Modifier.isStatic(modifiers)
						|| !mmm.getReturnType().equals(Void.TYPE)) {
					continue;
				}
				Class<?>[] ptypes = mmm.getParameterTypes();
				if (ptypes.length < 4 || !ptypes[1].equals(boolean.class)
						|| !ptypes[2].getName().equals("android.net.Uri")) {
					continue;
				}

				if (found == null) {
					found = mmm;
				} else {
					log("Error found multiple RN");
				}
			}
			if (found == null) {
				log("Error did not find RN");
			}
			return found;
		}

		// NotificationActionUtils.resendNotifications
		private Method findMethodNAURN() {
			Method found = null;
			for (final Method mmm : na_utils.getDeclaredMethods()) {
				final int modifiers = mmm.getModifiers();

				if (!Modifier.isPublic(modifiers)
						|| !Modifier.isStatic(modifiers)
						|| !mmm.getReturnType().equals(Void.TYPE)) {
					continue;
				}

				Class<?>[] ptypes = mmm.getParameterTypes();
				if (ptypes.length < 3 || !ptypes[0].equals(Context.class)
						|| !ptypes[1].getName().equals(PROVIDERS_ACCOUNT)
						|| !ptypes[2].getName().equals(PROVIDERS_FOLDER)) {
					continue;
				}
				if (found == null) {
					found = mmm;
				} else {
					log("Error found multiple RN");
				}
			}
			if (found == null) {
				log("Error did not find RN");
			}
			return found;
		}

		private void log(String logmsg) {
			XposedBridge.log("XGMAR.oHI:" + logmsg);
		}
	}

	private void hookGmail(LoadPackageParam lpparam) {
		new HookOnHandleIntent(lpparam.classLoader);
		new HookAddNotificationAction(lpparam.classLoader);
	}
}