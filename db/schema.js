import { pgTable, serial, text, numeric, timestamp, integer } from "drizzle-orm/pg-core";

// Users Table
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  telegramUserId: text("telegram_user_id").unique().default(null), // Store Telegram ID
  telegramUsername: text("telegram_username").default(null),
  createdAt: timestamp("created_at").defaultNow(),
});

// Wallets Table
export const wallets = pgTable("wallets", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  blockchain: text("blockchain").notNull(), // BTC, ETH, SOL, TRX
  privateKey: text("private_key").notNull(), // Store securely (encrypted)
  address: text("address").notNull(),
  threshold: numeric("threshold").notNull(),
  receiverAddress: text("receiver_address").notNull(),
  walletConnectUri: text("wallet_connect_uri").default(null), 
  createdAt: timestamp("created_at").defaultNow(),
});

// Transactions Table
export const transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  walletId: integer("wallet_id").references(() => wallets.id),
  blockchain: text("blockchain").notNull(),
  amount: numeric("amount").notNull(),
  status: text("status").notNull(), // pending, success, failed
  txHash: text("tx_hash"),
  createdAt: timestamp("created_at").defaultNow(),
});
