package com.torchat.app.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.torchat.app.ui.screens.*

/**
 * Navigation routes for the app.
 */
sealed class Screen(val route: String) {
    object Splash : Screen("splash")
    object Setup : Screen("setup")
    object Home : Screen("home")
    object Chat : Screen("chat/{contactId}") {
        fun createRoute(contactId: String) = "chat/$contactId"
    }
    object AddContact : Screen("add_contact")
    object Settings : Screen("settings")
    object Identity : Screen("identity")
    object Call : Screen("call/{contactId}") {
        fun createRoute(contactId: String) = "call/$contactId"
    }
}

/**
 * Main navigation host for TorChat.
 */
@Composable
fun TorChatNavHost(
    navController: NavHostController = rememberNavController()
) {
    NavHost(
        navController = navController,
        startDestination = Screen.Splash.route
    ) {
        composable(Screen.Splash.route) {
            SplashScreen(
                onNavigateToSetup = {
                    navController.navigate(Screen.Setup.route) {
                        popUpTo(Screen.Splash.route) { inclusive = true }
                    }
                },
                onNavigateToHome = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Splash.route) { inclusive = true }
                    }
                }
            )
        }

        composable(Screen.Setup.route) {
            SetupScreen(
                onSetupComplete = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Setup.route) { inclusive = true }
                    }
                }
            )
        }

        composable(Screen.Home.route) {
            HomeScreen(
                onNavigateToChat = { contactId ->
                    navController.navigate(Screen.Chat.createRoute(contactId))
                },
                onNavigateToAddContact = {
                    navController.navigate(Screen.AddContact.route)
                },
                onNavigateToSettings = {
                    navController.navigate(Screen.Settings.route)
                },
                onNavigateToIdentity = {
                    navController.navigate(Screen.Identity.route)
                }
            )
        }

        composable(Screen.Chat.route) { backStackEntry ->
            val contactId = backStackEntry.arguments?.getString("contactId") ?: return@composable
            ChatScreen(
                contactId = contactId,
                onNavigateBack = { navController.popBackStack() },
                onNavigateToCall = {
                    navController.navigate(Screen.Call.createRoute(contactId))
                }
            )
        }

        composable(Screen.AddContact.route) {
            AddContactScreen(
                onNavigateBack = { navController.popBackStack() },
                onContactAdded = {
                    navController.popBackStack()
                }
            )
        }

        composable(Screen.Settings.route) {
            SettingsScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }

        composable(Screen.Identity.route) {
            IdentityScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }

        composable(Screen.Call.route) { backStackEntry ->
            val contactId = backStackEntry.arguments?.getString("contactId") ?: return@composable
            CallScreen(
                contactId = contactId,
                onNavigateBack = { navController.popBackStack() }
            )
        }
    }
}
