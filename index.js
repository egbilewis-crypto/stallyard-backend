import { useMarketplaceRouting, readMarketplaceRoute, marketplaceRouteUrl, PRIVATE_VIEWS } from "./MarketplaceRoutes.js";
import React, { lazy, Suspense, useState, useEffect, useCallback, useRef } from "react";
import { Search, Plus, Store, LayoutGrid, Pencil, Trash2, X, PackageOpen, ShoppingBag, Minus, User, LogOut, Receipt, Shield, HelpCircle, Wallet, MessageCircle, Send, Heart, Bell, Image as ImageIcon, Flag, Eye, EyeOff } from "lucide-react";

// AWS Amplify's camera and face-liveness libraries are large and are only
// needed when a seller opens identity verification. Keep them out of the
// public marketplace bundle and download both the component and its CSS on
// demand. React.lazy requires a default export, so the named AWS component is
// adapted here without adding another source file.
const FaceLivenessDetectorCore = lazy(() =>
  Promise.all([
    import("@aws-amplify/ui-react-liveness"),
    import("@aws-amplify/ui-react-liveness/styles.css"),
  ]).then(([module]) => ({ default: module.FaceLivenessDetectorCore }))
);

// The complete privileged dashboard is kept out of the public marketplace
// bundle and fetched only after an authenticated admin opens the admin view.
const SuperAdminDashboard = lazy(() => import("./SuperAdminDashboard.jsx"));
const DriverDelivery = lazy(() => import("./DriverDelivery.jsx"));
const DriverDashboard = lazy(() => import("./DriverDashboard.jsx"));
const SellerDriverJobs = lazy(() => import("./SellerDriverJobs.jsx"));

const INK = "#1B2430";
const CANVAS = "#F6F3EC";
const MARIGOLD = "#E8A94D";
const BERRY = "#C1443C";
const SAGE = "#6B8F71";
const SLATE = "#667085";

const BACKEND_URL =
  typeof window !== "undefined" && /(^|\.)stallyard\.com$/i.test(window.location.hostname)
    ? "https://api.stallyard.com"
    : "https://stallyard-backend-production.up.railway.app";

// All Stallyard API requests include credentials so the backend can use a
// Secure, HttpOnly session cookie. Authentication tokens are never stored in
// localStorage or exposed to frontend JavaScript.
const backendFetch = async (url, options = {}) => {
  return fetch(url, {
    ...options,
    credentials: "include",
  });
};

// `window.storage` may not exist in every browser environment. On the real
// deployed site it doesn't exist, so we back it with the browser's own
// localStorage instead — same shape (get/set/delete/list), so nothing else
// in this file has to change.
if (typeof window !== "undefined" && !window.storage) {
  const PREFIX = "stallyard-storage:";
  window.storage = {
    async get(key) {
      const raw = localStorage.getItem(PREFIX + key);
      return raw === null ? null : { key, value: raw };
    },
    async set(key, value) {
      localStorage.setItem(PREFIX + key, value);
      return { key, value };
    },
    async delete(key) {
      const existed = localStorage.getItem(PREFIX + key) !== null;
      localStorage.removeItem(PREFIX + key);
      return { key, deleted: existed };
    },
    async list(prefix = "") {
      const keys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith(PREFIX + prefix)) keys.push(k.slice(PREFIX.length));
      }
      return { keys };
    },
  };
}

const CATEGORIES = [
  "Accessories",
  "Art",
  "Auto Parts",
  "Bags & Purses",
  "Bath & Beauty",
  "Books",
  "Clothing",
  "Collectibles",
  "Craft Supplies & Tools",
  "Electronics",
  "Gifts",
  "Groceries",
  "Handmade",
  "Home",
  "Jewelry",
  "Kids & Baby",
  "Movies & Music",
  "Office",
  "Outdoors",
  "Paper & Party Supplies",
  "Pet Supplies",
  "Shoes",
  "Tools & Equipment",
  "Toys & Games",
  "Vintage",
  "Weddings",
  "Other",
];

const SUBCATEGORIES = {
  "Accessories": [
    "Belts",
    "Hats & Caps",
    "Scarves & Wraps",
    "Sunglasses",
    "Eyewear",
    "Hair Accessories",
    "Gloves",
    "Wallets",
    "Keychains",
    "Umbrellas",
    "Watches",
    "Fashion Accessories",
    "Other Accessories"
  ],
  "Art": [
    "Paintings",
    "Drawings & Illustrations",
    "Prints",
    "Photography",
    "Sculpture",
    "Digital Art",
    "Wall Art",
    "African Art",
    "Mixed Media",
    "Art Supplies",
    "Posters",
    "Other Art"
  ],
  "Auto Parts": [
    "Engine Parts",
    "Transmission Parts",
    "Brakes",
    "Suspension & Steering",
    "Tires",
    "Wheels & Rims",
    "Batteries",
    "Alternators & Starters",
    "Filters",
    "Exhaust Parts",
    "Cooling System",
    "Fuel System",
    "Electrical Parts",
    "Headlights & Lighting",
    "Mirrors",
    "Body Parts",
    "Bumpers",
    "Doors & Windows",
    "Interior Parts",
    "Car Audio",
    "GPS & Electronics",
    "Tools & Equipment",
    "Motorcycle Parts",
    "Truck Parts",
    "Car Care Products",
    "Other Auto Parts"
  ],
  "Bags & Purses": [
    "Handbags",
    "Shoulder Bags",
    "Crossbody Bags",
    "Tote Bags",
    "Backpacks",
    "Clutches",
    "Wallets",
    "Travel Bags",
    "Laptop Bags",
    "School Bags",
    "Briefcases",
    "Luggage",
    "Cosmetic Bags",
    "Other Bags"
  ],
  "Bath & Beauty": [
    "Skin Care",
    "Hair Care",
    "Makeup",
    "Fragrances",
    "Bath Products",
    "Body Care",
    "Nail Care",
    "Shaving & Grooming",
    "Beauty Tools",
    "Hair Extensions & Wigs",
    "Natural Beauty Products",
    "Men's Grooming",
    "Other Beauty Products"
  ],
  "Books": [
    "Fiction",
    "Nonfiction",
    "Children's Books",
    "Textbooks",
    "Academic Books",
    "Religious Books",
    "Business Books",
    "Self-Help",
    "Cookbooks",
    "Comics & Graphic Novels",
    "Magazines",
    "Dictionaries",
    "Exam Preparation",
    "Used Books",
    "Rare Books",
    "Other Books"
  ],
  "Clothing": [
    "Men's Clothing",
    "Women's Clothing",
    "Boys' Clothing",
    "Girls' Clothing",
    "Dresses",
    "Shirts",
    "T-Shirts",
    "Trousers",
    "Jeans",
    "Shorts",
    "Skirts",
    "Suits",
    "Jackets & Coats",
    "Sweaters",
    "Sportswear",
    "Underwear",
    "Sleepwear",
    "Swimwear",
    "Traditional Nigerian Clothing",
    "Maternity Clothing",
    "Uniforms",
    "Other Clothing"
  ],
  "Collectibles": [
    "Coins",
    "Stamps",
    "Trading Cards",
    "Sports Memorabilia",
    "Music Memorabilia",
    "Movie Memorabilia",
    "Historical Memorabilia",
    "Figurines",
    "Dolls",
    "Antiques",
    "Vintage Collectibles",
    "Autographs",
    "Advertising Collectibles",
    "African Collectibles",
    "Other Collectibles"
  ],
  "Craft Supplies & Tools": [
    "Beads",
    "Fabric",
    "Yarn",
    "Sewing Supplies",
    "Knitting Supplies",
    "Crochet Supplies",
    "Jewelry Making",
    "Leatherworking",
    "Woodworking",
    "Painting Supplies",
    "Drawing Supplies",
    "Sculpting Supplies",
    "Candle Making",
    "Soap Making",
    "Floral Supplies",
    "Craft Tools",
    "Other Craft Supplies"
  ],
  "Electronics": [
    "Mobile Phones",
    "Smartphones",
    "Tablets",
    "Laptops",
    "Desktop Computers",
    "Computer Components",
    "Computer Accessories",
    "Monitors",
    "Televisions",
    "Projectors",
    "Cameras",
    "Camera Accessories",
    "Video Cameras",
    "Headphones",
    "Earbuds",
    "Speakers",
    "Home Audio",
    "Gaming Consoles",
    "Video Games",
    "Gaming Controllers",
    "Gaming Accessories",
    "Smart Watches",
    "Wearable Technology",
    "Chargers & Cables",
    "Power Banks",
    "Routers & Networking",
    "Printers & Scanners",
    "Storage Devices",
    "Security Cameras",
    "Smart Home Devices",
    "Media Players",
    "Electronic Accessories",
    "Other Electronics"
  ],
  "Gifts": [
    "Birthday Gifts",
    "Wedding Gifts",
    "Anniversary Gifts",
    "Graduation Gifts",
    "Baby Gifts",
    "Gifts for Him",
    "Gifts for Her",
    "Gifts for Kids",
    "Corporate Gifts",
    "Personalized Gifts",
    "Gift Sets",
    "Gift Cards",
    "Holiday Gifts",
    "Other Gifts"
  ],
  "Groceries": [
    "Rice & Grains",
    "Pasta & Noodles",
    "Flour & Baking",
    "Cooking Oil",
    "Spices & Seasonings",
    "Canned Foods",
    "Snacks",
    "Biscuits & Cookies",
    "Sweets & Chocolate",
    "Beverages",
    "Tea & Coffee",
    "Breakfast Foods",
    "Dairy Products",
    "Frozen Foods",
    "Fresh Produce",
    "Meat & Seafood",
    "Nigerian Food Products",
    "Health Foods",
    "Baby Food",
    "Other Groceries"
  ],
  "Handmade": [
    "Handmade Jewelry",
    "Handmade Clothing",
    "Handmade Bags",
    "Handmade Shoes",
    "Handmade Furniture",
    "Handmade Home Decor",
    "Handmade Art",
    "Handmade Toys",
    "Handmade Beauty Products",
    "Handmade Gifts",
    "Handmade Accessories",
    "Traditional Crafts",
    "Other Handmade Items"
  ],
  "Home": [
    "Furniture",
    "Living Room Furniture",
    "Bedroom Furniture",
    "Dining Furniture",
    "Office Furniture",
    "Home Decor",
    "Rugs & Carpets",
    "Curtains & Blinds",
    "Lighting",
    "Bedding",
    "Mattresses",
    "Kitchenware",
    "Cookware",
    "Dinnerware",
    "Small Appliances",
    "Major Appliances",
    "Storage & Organization",
    "Bathroom Accessories",
    "Cleaning Supplies",
    "Garden Tools",
    "Plants",
    "Pots & Planters",
    "Outdoor Furniture",
    "Lawn Equipment",
    "Grills & Outdoor Cooking",
    "Home Improvement",
    "Other Home Items"
  ],
  "Jewelry": [
    "Rings",
    "Necklaces",
    "Earrings",
    "Bracelets",
    "Anklets",
    "Chains",
    "Pendants",
    "Brooches",
    "Engagement Rings",
    "Wedding Rings",
    "Men's Jewelry",
    "Women's Jewelry",
    "Gold Jewelry",
    "Silver Jewelry",
    "Beaded Jewelry",
    "Costume Jewelry",
    "Traditional Jewelry",
    "Other Jewelry"
  ],
  "Kids & Baby": [
    "Baby Clothing",
    "Kids' Clothing",
    "Baby Shoes",
    "Kids' Shoes",
    "Diapers",
    "Baby Feeding",
    "Bottles",
    "Strollers",
    "Car Seats",
    "Cribs",
    "Baby Bedding",
    "Baby Furniture",
    "Baby Bath",
    "Maternity Products",
    "School Supplies",
    "Kids' Accessories",
    "Other Baby & Kids Items"
  ],
  "Movies & Music": [
    "DVDs",
    "Blu-rays",
    "CDs",
    "Vinyl Records",
    "Music Downloads/Media",
    "Movie Collectibles",
    "Music Collectibles",
    "Musical Instruments",
    "Guitars",
    "Keyboards & Pianos",
    "Drums",
    "DJ Equipment",
    "Studio Equipment",
    "Microphones",
    "Other Movies & Music"
  ],
  "Office": [
    "Office Furniture",
    "Printers & Scanners",
    "Stationery",
    "Filing & Storage",
    "Office Electronics",
    "School & Office Supplies",
    "Desk Accessories",
    "Packaging & Mailing",
    "Other Office Supplies"
  ],
  "Outdoors": [
    "Camping",
    "Hiking",
    "Fishing",
    "Cycling",
    "Sports Equipment",
    "Football",
    "Basketball",
    "Fitness Equipment",
    "Gym Equipment",
    "Running",
    "Swimming",
    "Hunting Accessories",
    "Outdoor Furniture",
    "Garden Equipment",
    "Travel Gear",
    "Other Outdoor Items"
  ],
  "Paper & Party Supplies": [
    "Invitations",
    "Greeting Cards",
    "Gift Wrap",
    "Gift Bags",
    "Stickers",
    "Stationery",
    "Notebooks",
    "Journals",
    "Party Decorations",
    "Balloons",
    "Cake Decorations",
    "Party Favors",
    "Event Supplies",
    "Other Party Supplies"
  ],
  "Pet Supplies": [
    "Dog Supplies",
    "Cat Supplies",
    "Bird Supplies",
    "Fish & Aquarium Supplies",
    "Pet Food",
    "Pet Beds",
    "Collars & Leashes",
    "Pet Clothing",
    "Pet Toys",
    "Grooming Supplies",
    "Pet Carriers",
    "Other Pet Supplies"
  ],
  "Shoes": [
    "Men's Shoes",
    "Women's Shoes",
    "Boys' Shoes",
    "Girls' Shoes",
    "Sneakers",
    "Sandals",
    "Slippers",
    "Boots",
    "Heels",
    "Flats",
    "Formal Shoes",
    "Work Shoes",
    "Sports Shoes",
    "Traditional Footwear",
    "Other Shoes"
  ],
  "Tools & Equipment": [
    "Hand Tools",
    "Power Tools",
    "Measuring Tools",
    "Workshop Equipment",
    "Safety Equipment",
    "Tool Storage",
    "Welding Equipment",
    "Construction Tools",
    "Agricultural Tools",
    "Other Tools & Equipment"
  ],
  "Toys & Games": [
    "Action Figures",
    "Dolls",
    "Educational Toys",
    "Building Toys",
    "Baby Toys",
    "Outdoor Toys",
    "Remote-Control Toys",
    "Board Games",
    "Card Games",
    "Puzzles",
    "Video Games",
    "Gaming Accessories",
    "Stuffed Animals",
    "Other Toys & Games"
  ],
  "Vintage": [
    "Vintage Clothing",
    "Vintage Jewelry",
    "Vintage Furniture",
    "Vintage Home Decor",
    "Vintage Electronics",
    "Vintage Books",
    "Vintage Toys",
    "Vintage Bags",
    "Vintage Shoes",
    "Vintage Collectibles",
    "Other Vintage Items"
  ],
  "Weddings": [
    "Wedding Dresses",
    "Bridesmaid Dresses",
    "Groom & Groomsmen",
    "Wedding Shoes",
    "Wedding Jewelry",
    "Wedding Accessories",
    "Invitations",
    "Decorations",
    "Cake Accessories",
    "Wedding Favors",
    "Bridal Shower",
    "Traditional Wedding Items",
    "Wedding Gifts",
    "Other Wedding Supplies"
  ],
  "Other": [
    "Business & Industrial",
    "Office Supplies",
    "Medical Supplies",
    "Agricultural Equipment",
    "Construction Equipment",
    "Tools & Machinery",
    "Renewable Energy",
    "Solar Equipment",
    "Safety Equipment",
    "Miscellaneous"
  ]
};

const CONDITIONS = ["New", "Used", "Like New", "Good", "Fair", "Refurbished", "For parts / not working"];

const NIGERIAN_STATES = [
  "Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi", "Bayelsa", "Benue", "Borno",
  "Cross River", "Delta", "Ebonyi", "Edo", "Ekiti", "Enugu", "Gombe", "Imo", "Jigawa",
  "Kaduna", "Kano", "Katsina", "Kebbi", "Kogi", "Kwara", "Lagos", "Nasarawa", "Niger",
  "Ogun", "Ondo", "Osun", "Oyo", "Plateau", "Rivers", "Sokoto", "Taraba", "Yobe", "Zamfara",
  "FCT (Abuja)",
];

const MIN_LISTING_PHOTOS = 3;
const MAX_LISTING_PHOTOS = 12;
const MAX_LISTING_PHOTO_BYTES = 12 * 1024 * 1024; // 12 MB
const MIN_LISTING_PHOTO_DIM = 500; // reject below this
const RECOMMENDED_LISTING_PHOTO_DIM = 1200; // warn (not block) below this
const ACCEPTED_PHOTO_TYPES = ["image/jpeg", "image/jpg", "image/png", "image/webp", "image/heic", "image/heif", "image/avif"];

const SHIPPING_METHODS = [
  { value: "dhl", label: "DHL" },
  { value: "self_delivery", label: "Self delivery" },
  { value: "local_delivery_driver", label: "Local Delivery Driver" },
];

const RETURN_POLICIES = ["No returns", "7-day returns", "14-day returns", "30-day returns"];

const POLICY_LABELS = {
  seller_rules: "Seller rules",
  prohibited_items: "Prohibited items",
  fees: "Fees",
  payment_rules: "Payment rules",
  shipping_rules: "Shipping rules",
  returns_disputes: "Returns & disputes",
};
const POLICY_ORDER = ["seller_rules", "prohibited_items", "fees", "payment_rules", "shipping_rules", "returns_disputes"];

const TICKET_STATUS_LABEL = { open: "Open", in_progress: "In progress", resolved: "Resolved" };

// Dedicated admin origin. The public marketplace never renders the admin
// dashboard; authentication and authorization are still enforced by the backend.
const ADMIN_HOSTNAME = "admin.stallyard.com";
const ADMIN_URL = "https://admin.stallyard.com";
const ADMIN_SESSION_IDLE_MS = 30 * 60 * 1000;
const ADMIN_SESSION_STORAGE_KEY = "stallyard-admin-unlocked-until";
const ADMIN_TAB_STORAGE_KEY = "stallyard-admin-selected-tab";

function isAdminHost() {
  return typeof window !== "undefined" && window.location.hostname.toLowerCase() === ADMIN_HOSTNAME;
}

const ADMIN_ROLE_LABELS = {
  super_admin: "Super Admin",
  seller_verification: "Seller Verification",
  listing_moderator: "Listing Moderator",
  order_dispute: "Order/Dispute Admin",
  finance: "Finance Admin",
  customer_support: "Customer Support",
};
const ADMIN_ROLE_ORDER = [
  "super_admin", "seller_verification", "listing_moderator", "order_dispute", "finance", "customer_support",
];

// Mirrors the backend's permission matrix exactly, so the UI only shows
// what a role can actually do — the backend is still the real enforcement,
// this just keeps the interface from being confusing/misleading.
const ADMIN_ROLE_PERMISSIONS = {
  seller_verification: new Set(["seller_verification"]),
  listing_moderator: new Set(["listing_moderation"]),
  order_dispute: new Set(["dispute_resolution", "order_access", "order_management", "seller_report_review"]),
  finance: new Set(["finance", "order_access"]),
  customer_support: new Set(["support_tickets", "message_moderation", "seller_report_review"]),
};
function hasAdminPermission(member, permission) {
  if (!member?.isAdmin) return false;
  if (!member.adminRole || member.adminRole === "super_admin") return true;
  const allowed = ADMIN_ROLE_PERMISSIONS[member.adminRole];
  return allowed ? allowed.has(permission) : false;
}

const LISTING_MANAGE_TABS = [
  { key: "all", label: "All" },
  { key: "approved", label: "Active" },
  { key: "draft", label: "Draft" },
  { key: "pending", label: "Pending" },
  { key: "paused", label: "Paused" },
  { key: "sold", label: "Sold out" },
  { key: "rejected", label: "Rejected" },
  { key: "removed", label: "Taken down" },
];

const CURRENCIES = {
  NGN: { symbol: "₦", label: "Nigerian Naira (NGN)" },
};

function formatMoney(amount, currency) {
  const symbol = CURRENCIES.NGN.symbol;
  const num = Number(amount || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return `${symbol}${num}`;
}

// New listing uploads end in "-1600.webp" and have matching 400/800/1200
// variants. Older listing URLs safely return no srcset and continue using src.
function responsiveListingSrcSet(url) {
  const value = String(url || "");
  if (!/-1600\.webp(?:\?.*)?$/i.test(value)) return undefined;
  return [400, 800, 1200, 1600]
    .map((width) => `${value.replace(/-1600\.webp(?=\?|$)/i, `-${width}.webp`)} ${width}w`)
    .join(", ");
}

function toLocalDateTimeInput(value) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  const local = new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

function formatDeliveryDate(value) {
  const date = String(value || "").slice(0, 10);
  if (!date) return "";
  const [year, month, day] = date.split("-").map(Number);
  return new Date(year, month - 1, day).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

const CONDITION_COLOR = {
  New: "#6B8F71",
  Used: "#667085",
  "Like New": "#3B6E8F",
  Good: "#8A6D3B",
  Fair: "#B8862E",
  Refurbished: "#A6567A",
  "For parts / not working": "#C1443C",
};

const CATEGORY_COLOR = {
  Handmade: "#C1443C",
  Home: "#6B8F71",
  Vintage: "#8A6D3B",
  Electronics: "#3B6E8F",
  Clothing: "#A6567A",
  Books: "#4B5D67",
  Art: "#B8862E",
  Jewelry: "#9A6A85",
  Collectibles: "#806B55",
  "Bags & Purses": "#8B6757",
  "Craft Supplies & Tools": "#7C6A9A",
  "Paper & Party Supplies": "#A66F5C",
  Weddings: "#9A7B87",
  Accessories: "#657A8A",
  "Movies & Music": "#625D8A",
  Office: "#5E7184",
  "Kids & Baby": "#7E8F72",
  "Toys & Games": "#8A7650",
  "Bath & Beauty": "#8A6D83",
  Shoes: "#6E625A",
  "Tools & Equipment": "#59636F",
  "Pet Supplies": "#5F7D70",
  Gifts: "#9A624D",
  Outdoors: "#3E7A4E",
  "Auto Parts": "#4A4E58",
  Groceries: "#7A9E5C",
  Other: "#667085",
};

const CATEGORY_ICON = {
  Handmade: "🧶",
  Home: "🏠",
  Vintage: "🕰️",
  Electronics: "🔌",
  Clothing: "👕",
  Books: "📚",
  Art: "🎨",
  Jewelry: "💍",
  Collectibles: "🏺",
  "Bags & Purses": "👜",
  "Craft Supplies & Tools": "✂️",
  "Paper & Party Supplies": "🎉",
  Weddings: "💒",
  Accessories: "⌚",
  "Movies & Music": "🎵",
  Office: "🗂️",
  "Kids & Baby": "👶",
  "Toys & Games": "🧸",
  "Bath & Beauty": "🧴",
  Shoes: "👟",
  "Tools & Equipment": "🛠️",
  "Pet Supplies": "🐾",
  Gifts: "🎁",
  Outdoors: "🥾",
  "Auto Parts": "🚗",
  Groceries: "🛒",
  Other: "📦",
};

const EMOJI_CHOICES = ["📦", "🧶", "🕯️", "📚", "🪴", "👕", "🎨", "⌚", "🛠️", "🎧", "🧸", "🥾", "☕", "💍", "🪑", "🎸", "🚗", "⚙️", "🔧", "🛞", "🔋", "🛒", "🥕", "🍎"];

const FULFILLMENT_LABEL = {
  new: "New",
  preparing: "Preparing",
  shipped: "Shipped",
  delivered: "Delivered",
  cancelled: "Cancelled",
  returned: "Returned",
};

const FULFILLMENT_COLOR = {
  new: "#3B6E8F",
  preparing: "#B8862E",
  shipped: "#6B8F71",
  delivered: "#2F6B3A",
  cancelled: "#C1443C",
  returned: "#B8862E",
};

const SHIPPING_CARRIERS = ["DHL", "Self delivery", "Local Delivery Driver"];

const RETURN_REASONS = [
  "Not as described",
  "Damaged or defective",
  "Wrong item received",
  "Fake or counterfeit",
  "Item missing / never arrived",
  "Changed my mind",
  "Other",
];

const RETURN_STATUS_LABEL = {
  requested: "Return requested",
  approved: "Return approved",
  denied: "Return denied",
};

const RETURN_STATUS_COLOR = {
  requested: "#B8862E",
  approved: "#6B8F71",
  denied: "#C1443C",
};

function useFonts() {
  useEffect(() => {
    const id = "stallyard-fonts";
    if (document.getElementById(id)) return;
    const link = document.createElement("link");
    link.id = id;
    link.rel = "stylesheet";
    link.href =
      "https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=Work+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@500;600&display=swap";
    document.head.appendChild(link);
  }, []);
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test((email || "").trim());
}

// Permissive check: allows international formats, just makes sure it's
// mostly digits of a plausible length rather than enforcing one country's format.
function isValidPhone(phone) {
  const trimmed = (phone || "").trim();
  const digits = trimmed.replace(/[^0-9]/g, "");
  return trimmed.startsWith("+") && digits.length >= 8 && digits.length <= 15;
}

const NIGERIA_COUNTRY_ALIASES = ["nigeria", "ng"];
function isNigeria(country) {
  return NIGERIA_COUNTRY_ALIASES.includes((country || "").trim().toLowerCase());
}

// Stallyard is Nigeria-only. Seller verification is handled through the
// normal seller-approval flow rather than a country/currency sales threshold.
const needsLegacySalesThresholdVerification = false;

function orderNumber(id) {
  const numericId = String(id ?? "").replace(/\D/g, "");
  if (numericId) return `STY-${numericId.padStart(6, "0")}`;

  const safeId = String(id ?? "").replace(/[^a-z0-9]/gi, "").slice(-8).toUpperCase();
  return `STY-${safeId}`;
}

function formatTimeRemaining(endTime, now) {
  const ms = endTime - now;
  if (ms <= 0) return null;
  const totalMinutes = Math.floor(ms / 60000);
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  if (days > 0) return `${days}d ${hours}h left`;
  if (hours > 0) return `${hours}h ${minutes}m left`;
  return `${minutes}m left`;
}

// Converts the backend's snake_case /signup and /login response into the
// camelCase member shape the rest of this app expects. `existing` (if the
// username already has a local record) is merged in for fields the backend
// doesn't track yet — vacation mode, ID verification details, etc. — so
// logging in again doesn't wipe out local-only data.
function backendListingToFrontend(row, existing) {
  return {
    ...existing,
    id: row.id,
    ownerId: row.owner_id,
    title: row.title,
    description: row.description || "",
    price: Number(row.price),
    category: row.category,
    subcategory: row.subcategory || "",
    condition: row.condition,
    shippingFee: Number(row.shipping_fee) || 0,
    emoji: row.emoji || "📦",
    fitMake: row.fit_make || "",
    fitModel: row.fit_model || "",
    fitYear: row.fit_year || "",
    images: (row.images || []).filter((url) => !(row.hidden_image_urls || []).includes(url)),
    allImages: row.images || [],
    hiddenImageUrls: row.hidden_image_urls || [],
    flaggedImages: row.flagged_images || [],
    listingType: row.listing_type || "fixed",
    currency: row.currency || "NGN",
    status: row.status === "approved" ? "active" : (row.status || "pending"),
    isFeatured: !!row.is_featured,
    auctionEndTime: row.auction_end_time ? new Date(row.auction_end_time).getTime() : null,
    bidHistory: row.bid_history || [],
    highestBidderUsername: row.highest_bidder_username || null,
    quantity: row.quantity ?? "",
    sku: row.sku || "",
    brand: row.brand || "",
    state: row.state || "",
    shippingMethods: row.shipping_methods || [],
    returnPolicy: row.return_policy || "",
    vin: row.vin || "",
    sellerName: row.seller_name,
    ownerUsername: row.owner_username,
    createdAt: row.created_at ? new Date(row.created_at).getTime() : existing?.createdAt || Date.now(),
  };
}

function backendMessageToFrontend(row, members) {
  const sender = members.find((m) => m.backendId === row.sender_id);
  return {
    id: row.id,
    type: row.message_type,
    senderUsername: sender?.username,
    text: row.body || "",
    amount: row.offer_amount != null ? Number(row.offer_amount) : undefined,
    status: row.offer_status,
    imageUrl: row.image_url || "",
    orderId: row.order_id || null,
    createdAt: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
  };
}

function backendThreadToFrontend(row, messageRows, members, listings) {
  const buyer = members.find((m) => m.backendId === row.buyer_id);
  const seller = members.find((m) => m.backendId === row.seller_id);
  const listing = listings.find((l) => l.id === row.listing_id);
  const messages = messageRows.map((m) => backendMessageToFrontend(m, members));
  return {
    id: row.id,
    listingId: row.listing_id,
    listingTitle: listing?.title || "Listing",
    listingEmoji: listing?.emoji || "📦",
    buyerUsername: buyer?.username,
    buyerName: buyer?.displayName,
    sellerUsername: seller?.username,
    sellerName: seller?.displayName,
    messages,
    updatedAt: messages.length > 0 ? Math.max(...messages.map((m) => m.createdAt)) : (row.created_at ? new Date(row.created_at).getTime() : Date.now()),
  };
}

function backendReviewToFrontend(row, members) {
  const buyer = members.find((m) => m.backendId === row.buyer_id);
  const seller = members.find((m) => m.backendId === row.seller_id);
  return {
    id: row.id,
    orderId: row.order_id,
    listingId: row.listing_id,
    sellerUsername: seller?.username,
    buyerUsername: buyer?.username,
    buyerName: buyer?.displayName,
    rating: row.rating,
    comment: row.comment || "",
    sellerResponse: row.seller_response || "",
    sellerResponseAt: row.seller_response_at ? new Date(row.seller_response_at).getTime() : null,
    createdAt: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
  };
}

function backendOrderToFrontend(row) {
  return {
    id: row.id,
    buyerId: row.buyer_id,
    buyerUsername: row.buyer_username,
    buyerName: row.buyer_name || row.buyer_username,
    shippingAddress: row.shipping_address || {},
    currency: row.currency || "NGN",
    subtotal: Number(row.subtotal) || 0,
    shippingTotal: Number(row.shipping_total) || 0,
    total: Number(row.total) || 0,
    commissionRate: row.commission_rate !== undefined ? Number(row.commission_rate) : 0.05,
    commissionAmount: Number(row.commission_amount) || 0,
    taxAmount: Number(row.tax_amount) || 0,
    paymentStatus: row.payment_status || "held",
    paystackReference: row.paystack_reference || null,
    paymentChannel: row.payment_channel || null,
    paymentCardType: row.payment_card_type || null,
    paymentBank: row.payment_bank || null,
    paymentLast4: row.payment_last4 || null,
    refundStatus: row.refund_status || null,
    paystackRefundId: row.paystack_refund_id || null,
    refundType: row.refund_type || null,
    refundAmount: Number(row.refund_amount) || 0,
    cancellationFee: Number(row.cancellation_fee) || 0,
    buyerExitType: row.buyer_exit_type || null,
    refundReason: row.refund_reason || "",
    refundRequestedBy: row.refund_requested_by || null,
    refundRequestedAt: row.refund_requested_at ? new Date(row.refund_requested_at).getTime() : null,
    refundPreviousPaymentStatus: row.refund_previous_payment_status || null,
    refundFailureReason: row.refund_failure_reason || "",
    refundedAt: row.refunded_at ? new Date(row.refunded_at).getTime() : null,
    refundUpdatedAt: row.refund_updated_at ? new Date(row.refund_updated_at).getTime() : null,
    isDisputed: !!row.is_disputed,
    payouts: (row.payouts || []).map((p) => ({
      id: p.id,
      sellerId: p.seller_id,
      amount: Number(p.amount) || 0,
      status: p.status || "queued",
      reference: p.paystack_reference || "",
      failureReason: p.failure_reason || "",
      createdAt: p.created_at ? new Date(p.created_at).getTime() : null,
      completedAt: p.completed_at ? new Date(p.completed_at).getTime() : null,
    })),
    createdAt: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
    items: (row.items || []).map((i) => ({
      id: i.id,
      listingId: i.listing_id,
      title: i.title,
      emoji: i.emoji || "📦",
      price: Number(i.price),
      qty: i.qty,
      shippingFee: Number(i.shipping_fee) || 0,
      sellerName: i.seller_name,
      sellerId: i.seller_id,
      ownerUsername: i.seller_username,
      fulfillmentStatus: i.fulfillment_status || "new",
      trackingNumber: i.tracking_number || "",
      carrier: i.carrier || "",
      selfDeliveryStatus: i.self_delivery_status || null,
      deliveryPersonSelfieUrl: i.delivery_person_selfie_url || "",
      selfDeliveryStartedAt: i.self_delivery_started_at ? new Date(i.self_delivery_started_at).getTime() : null,
      selfDeliveryOnMyWayAt: i.self_delivery_on_my_way_at ? new Date(i.self_delivery_on_my_way_at).getTime() : null,
      selfDeliveryArrivedAt: i.self_delivery_arrived_at ? new Date(i.self_delivery_arrived_at).getTime() : null,
      selfDeliveryDeliveredAt: i.self_delivery_delivered_at ? new Date(i.self_delivery_delivered_at).getTime() : null,
      estimatedDeliveryStart: i.estimated_delivery_start ? String(i.estimated_delivery_start).slice(0, 10) : "",
      estimatedDeliveryEnd: i.estimated_delivery_end ? String(i.estimated_delivery_end).slice(0, 10) : "",
      liveLocationEnabled: !!i.live_location_enabled,
      liveLocationLatitude: i.live_location_latitude === null || i.live_location_latitude === undefined ? null : Number(i.live_location_latitude),
      liveLocationLongitude: i.live_location_longitude === null || i.live_location_longitude === undefined ? null : Number(i.live_location_longitude),
      liveLocationAccuracy: i.live_location_accuracy === null || i.live_location_accuracy === undefined ? null : Number(i.live_location_accuracy),
      liveLocationUpdatedAt: i.live_location_updated_at ? new Date(i.live_location_updated_at).getTime() : null,
      liveLocationExpiresAt: i.live_location_expires_at ? new Date(i.live_location_expires_at).getTime() : null,
      buyerConfirmedAt: i.buyer_confirmed_at ? new Date(i.buyer_confirmed_at).getTime() : null,
      shippedAt: i.shipped_at ? new Date(i.shipped_at).getTime() : null,
      proofOfDeliveryUrl: i.proof_of_delivery_url || "",
      // Secret delivery token is returned only on buyer-facing order responses.
      deliveryToken: i.delivery_token || null,
      deliveryTokenGeneratedAt: i.delivery_token_generated_at ? new Date(i.delivery_token_generated_at).getTime() : null,
      deliveryTokenSentAt: i.delivery_token_sent_at ? new Date(i.delivery_token_sent_at).getTime() : null,
      deliveryTokenRedeemedAt: i.delivery_token_redeemed_at ? new Date(i.delivery_token_redeemed_at).getTime() : null,
      cancellationStatus: i.cancellation_status || null,
      cancellationReason: i.cancellation_reason || "",
      cancellationRequestedAt: i.cancellation_requested_at ? new Date(i.cancellation_requested_at).getTime() : null,
      cancellationRespondedAt: i.cancellation_responded_at ? new Date(i.cancellation_responded_at).getTime() : null,
      returnStatus: i.return_status || null,
      returnReason: i.return_reason || "",
      returnNote: i.return_note || "",
      returnRequestedAt: i.return_requested_at ? new Date(i.return_requested_at).getTime() : null,
      returnTrackingNumber: i.return_tracking_number || "",
      returnEvidenceUrls: i.return_evidence_urls || [],
      statusHistory: Array.isArray(i.status_history) && i.status_history.length > 0
        ? i.status_history.map((event) => ({
            status: event.event_type || "updated",
            label: event.label || "Order updated",
            details: event.details || {},
            at: event.created_at ? new Date(event.created_at).getTime() : Date.now(),
          }))
        : [{ status: "order_placed", label: "Order placed", at: row.created_at ? new Date(row.created_at).getTime() : Date.now() }],
    })),
  };
}

function backendUserToMember(user, existing) {
  return {
    ...existing,
    backendId: user.id,
    username: user.username,
    displayName: user.display_name || user.username,
    email: user.email,
    phone: user.phone || existing?.phone || "",
    firstName: user.first_name || existing?.firstName || "",
    lastName: user.last_name || existing?.lastName || "",
    otherName: user.other_name || existing?.otherName || "",
    dateOfBirth: user.date_of_birth ? String(user.date_of_birth).slice(0, 10) : existing?.dateOfBirth || "",
    gender: user.gender || existing?.gender || "",
    nationality: user.nationality || existing?.nationality || "",
    stateOfResidence: user.state_of_residence || existing?.stateOfResidence || "",
    officeLocation: user.office_location || existing?.officeLocation || "",
    avatarUrl: user.avatar_url ?? existing?.avatarUrl ?? "",
    storeBio: user.store_bio ?? existing?.storeBio ?? "",
    storePolicies: user.store_policies ?? existing?.storePolicies ?? "",
    twoFactorEnabled: user.two_factor_enabled ?? existing?.twoFactorEnabled ?? false,
    adminRole: user.admin_role ?? existing?.adminRole ?? null,
    isEmailVerified: user.is_email_verified ?? existing?.isEmailVerified ?? false,
    isPhoneVerified: user.is_phone_verified ?? existing?.isPhoneVerified ?? false,
    profileComplete: user.profile_complete ?? existing?.profileComplete ?? false,
    country: user.country || existing?.country || "",
    isAdmin: !!user.is_admin,
    isApproved: !!user.is_approved,
    isVerified: !!user.is_verified,
    isSuspended: !!user.is_suspended,
    isPreview: !!(user.is_preview ?? existing?.isPreview),
    joinedAt: user.created_at ? new Date(user.created_at).getTime() : existing?.joinedAt || Date.now(),
    accountType: user.account_type || existing?.accountType || "personal",
    onboardingIntent: user.onboarding_intent || existing?.onboardingIntent || "buy",
    onboardingCompletedAt: user.onboarding_completed_at || existing?.onboardingCompletedAt || null,
    licenseNumber: user.license_number || existing?.licenseNumber || "",
    idType: user.id_type || existing?.idType || "Passport",
    idCountry: user.id_country || existing?.idCountry || "",
    licensePhotos: user.license_photos || existing?.licensePhotos || [],
    idVerificationExempt:
      user.id_verification_exempt ?? existing?.idVerificationExempt ?? false,
    hasAppliedToSell: user.has_applied_to_sell || existing?.hasAppliedToSell || false,
    verificationStatus:
      user.verification_status ||
      existing?.verificationStatus ||
      (user.is_approved ? "approved" : user.has_applied_to_sell ? "pending" : "none"),
    bankStatementUrl: user.bank_statement_url ?? existing?.bankStatementUrl ?? null,
    rejectionReason: user.rejection_reason ?? existing?.rejectionReason ?? "",
    casualSellerStatus: user.casual_seller_status ?? existing?.casualSellerStatus ?? "none",
    casualSellerLimit: Number(user.casual_seller_limit ?? existing?.casualSellerLimit ?? 500000),
    casualSellerApprovedAt: user.casual_seller_approved_at ?? existing?.casualSellerApprovedAt ?? null,
    sellerTier: user.seller_tier ?? existing?.sellerTier ?? (user.is_approved ? "verified" : "buyer"),
    sellerListingLimit: Number(user.seller_listing_limit ?? existing?.sellerListingLimit ?? 20000000),
    sellerSuspended: !!(user.seller_suspended ?? existing?.sellerSuspended),
    sellerSuspendedReason: user.seller_suspended_reason ?? existing?.sellerSuspendedReason ?? "",
    phoneVerified: existing?.phoneVerified || true,
    vacationMode: existing?.vacationMode || false,
  };
}

// Basic, non-exhaustive filter to discourage sharing emails/phone numbers in chat.
// It catches common patterns but a determined user could still obfuscate around it
// (e.g. "call me at five five five..."), so this is a nudge, not a guarantee.
function containsContactInfo(text) {
  const emailPattern = /[a-z0-9._%+-]+\s*(@|\bat\b)\s*[a-z0-9.-]+\s*(\.|\bdot\b)\s*[a-z]{2,}/i;
  const digitsOnly = text.replace(/[^0-9]/g, "");
  const phonePattern = /(\+?\d[\s.\-()]*){7,}/;
  const hasManyDigitsClustered = phonePattern.test(text) && digitsOnly.length >= 7;
  return emailPattern.test(text) || hasManyDigitsClustered;
}

// Best-effort carrier detection from common tracking number formats.
// Falls back to a general web search if the format isn't recognized —
// this app has no live carrier API integration, so it can't confirm
// the number is valid or show real-time scan events itself.
// Lightweight, dependency-free parsing — just enough to show something
// readable like "Chrome on Windows" rather than a raw user-agent string.
function describeUserAgent(ua) {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Chrome\//.test(ua)
    ? "Chrome"
    : /Firefox\//.test(ua)
    ? "Firefox"
    : /Safari\//.test(ua)
    ? "Safari"
    : "Browser";
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Mac OS X/.test(ua)
    ? "Mac"
    : /Android/.test(ua)
    ? "Android"
    : /iPhone|iPad|iPod/.test(ua)
    ? "iOS"
    : /Linux/.test(ua)
    ? "Linux"
    : "an unknown device";
  return `${browser} on ${os}`;
}

function buildTrackingUrl(raw) {
  const num = raw.trim();
  const digits = num.replace(/[^0-9]/g, "");
  if (/^1Z[0-9A-Z]{16}$/i.test(num.replace(/\s/g, ""))) {
    return `https://www.ups.com/track?tracknum=${encodeURIComponent(num.replace(/\s/g, ""))}`;
  }
  if (/^\d{12}$/.test(digits) || /^\d{15}$/.test(digits) || /^\d{20}$/.test(digits)) {
    return `https://www.fedex.com/fedextrack/?trknbr=${digits}`;
  }
  if (/^(94|93|92|95)\d{20}$/.test(digits) || /^\d{20,22}$/.test(digits)) {
    return `https://tools.usps.com/go/TrackConfirmAction?tLabels=${digits}`;
  }
  if (/^\d{10,11}$/.test(digits) || /^(GM|JJD|JVGL)[0-9A-Z]{8,}$/i.test(num.replace(/\s/g, ""))) {
    return `https://www.dhl.com/global-en/home/tracking.html?tracking-id=${encodeURIComponent(num.replace(/\s/g, ""))}`;
  }
  return `https://www.google.com/search?q=${encodeURIComponent("track package " + num)}`;
}

function resizeImageFile(file, maxDim = 900, quality = 0.75) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Couldn't read file"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("Couldn't read image"));
      img.onload = () => {
        let { width, height } = img;
        if (width > height && width > maxDim) {
          height = Math.round((height * maxDim) / width);
          width = maxDim;
        } else if (height > maxDim) {
          width = Math.round((width * maxDim) / height);
          height = maxDim;
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        canvas.getContext("2d").drawImage(img, 0, 0, width, height);
        resolve(canvas.toDataURL("image/jpeg", quality));
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

// Homepage hero images are the page's LCP resource. Desktop creatives use a
// wide 4:1 frame; mobile creatives use a square frame so important content is
// never lost to aggressive responsive cropping. Both are encoded as WebP.
function resizeHomepageHero(file, variant = "desktop") {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Couldn't read file"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("Couldn't read image"));
      img.onload = async () => {
        try {
          const isMobile = variant === "mobile";
          const targetRatio = isMobile ? 1 : 4;
          const maxBytes = (isMobile ? 180 : 250) * 1024;
          const sourceRatio = img.width / img.height;
          let sx = 0;
          let sy = 0;
          let sourceWidth = img.width;
          let sourceHeight = img.height;
          if (sourceRatio > targetRatio) {
            sourceWidth = Math.round(img.height * targetRatio);
            sx = Math.round((img.width - sourceWidth) / 2);
          } else if (sourceRatio < targetRatio) {
            sourceHeight = Math.round(img.width / targetRatio);
            sy = Math.round((img.height - sourceHeight) / 2);
          }

          const widths = isMobile ? [800, 720, 640] : [1600, 1440, 1280, 1120];
          const qualities = [0.82, 0.74, 0.66, 0.58, 0.5];
          let best = null;
          for (const requestedWidth of widths) {
            const width = Math.max(1, Math.min(requestedWidth, sourceWidth));
            const height = Math.max(1, Math.round(width / targetRatio));
            const canvas = document.createElement("canvas");
            canvas.width = width;
            canvas.height = height;
            canvas.getContext("2d").drawImage(img, sx, sy, sourceWidth, sourceHeight, 0, 0, width, height);
            for (const quality of qualities) {
              const blob = await new Promise((done) => canvas.toBlob(done, "image/webp", quality));
              if (!blob) continue;
              best = { blob, width, height };
              if (blob.size <= maxBytes) break;
            }
            if (best?.blob.size <= maxBytes) break;
          }
          if (!best) throw new Error("This browser couldn't create a WebP image");
          const outputReader = new FileReader();
          outputReader.onerror = () => reject(new Error("Couldn't prepare the optimized image"));
          outputReader.onload = () => resolve({
            dataUrl: outputReader.result,
            sizeBytes: best.blob.size,
            width: best.width,
            height: best.height,
          });
          outputReader.readAsDataURL(best.blob);
        } catch (error) {
          reject(error);
        }
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

// Used specifically for listing photos, where we need the ORIGINAL
// dimensions too (to reject/warn on low-resolution uploads before they
// ever get resized down) — kept separate from resizeImageFile above so
// the many other places that already call it (avatars, ID photos, review
// photos, etc) don't need to change what they expect back.
// Runs entirely in the browser, no external service — downsamples the
// photo to a small analysis size for speed, then checks two things:
// average brightness (catches too-dark or overexposed shots) and Laplacian
// variance (a standard, well-established blur estimator: a sharp photo has
// lots of fine edge detail, which the Laplacian highlights strongly; a
// blurry one is smooth, so the variance of that filtered image comes out
// low). The thresholds below are reasonable starting points, not exact
// science — the same way any auto-quality check needs a bit of tuning
// once real seller photos start coming through.
function analyzeImageQuality(img) {
  const SAMPLE_SIZE = 100;
  const canvas = document.createElement("canvas");
  canvas.width = SAMPLE_SIZE;
  canvas.height = SAMPLE_SIZE;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, SAMPLE_SIZE, SAMPLE_SIZE);
  const { data } = ctx.getImageData(0, 0, SAMPLE_SIZE, SAMPLE_SIZE);

  const gray = new Float32Array(SAMPLE_SIZE * SAMPLE_SIZE);
  let brightnessSum = 0;
  for (let i = 0; i < gray.length; i++) {
    const r = data[i * 4];
    const g = data[i * 4 + 1];
    const b = data[i * 4 + 2];
    const v = 0.299 * r + 0.587 * g + 0.114 * b;
    gray[i] = v;
    brightnessSum += v;
  }
  const brightness = brightnessSum / gray.length; // 0 (black) – 255 (white)

  // 3x3 Laplacian kernel over the grayscale grid, skipping the 1px border.
  const laplacian = [];
  for (let y = 1; y < SAMPLE_SIZE - 1; y++) {
    for (let x = 1; x < SAMPLE_SIZE - 1; x++) {
      const idx = y * SAMPLE_SIZE + x;
      const value =
        -4 * gray[idx] +
        gray[idx - 1] +
        gray[idx + 1] +
        gray[idx - SAMPLE_SIZE] +
        gray[idx + SAMPLE_SIZE];
      laplacian.push(value);
    }
  }
  const lapMean = laplacian.reduce((s, v) => s + v, 0) / laplacian.length;
  const blurVariance = laplacian.reduce((s, v) => s + (v - lapMean) ** 2, 0) / laplacian.length;

  return {
    brightness,
    blurVariance,
    isTooDark: brightness < 40,
    isTooBright: brightness > 225,
    isBlurry: blurVariance < 90,
  };
}

function resizeListingPhoto(file, maxDim = 1600, quality = 0.82) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Couldn't read file"));
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("Couldn't read image"));
      img.onload = () => {
        const originalWidth = img.width;
        const originalHeight = img.height;
        const quality_check = analyzeImageQuality(img);
        let { width, height } = img;
        if (width > height && width > maxDim) {
          height = Math.round((height * maxDim) / width);
          width = maxDim;
        } else if (height > maxDim) {
          width = Math.round((width * maxDim) / height);
          height = maxDim;
        }
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        canvas.getContext("2d").drawImage(img, 0, 0, width, height);
        resolve({
          dataUrl: canvas.toDataURL("image/jpeg", quality),
          originalWidth,
          originalHeight,
          ...quality_check,
        });
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Couldn't read file"));
    reader.onload = () => resolve(reader.result);
    reader.readAsDataURL(file);
  });
}

// Derives a single order-level status bucket (for tab filtering) from just
// one seller's items within an order, since an order can span multiple
// sellers and each item tracks its own fulfillment status independently.
function getSellerOrderStatus(order, username) {
  const myItems = order.items.filter((i) => i.ownerUsername === username);
  if (myItems.length === 0) return "new";
  if (myItems.every((i) => i.fulfillmentStatus === "cancelled")) return "cancelled";
  const relevant = myItems.filter((i) => i.fulfillmentStatus !== "cancelled");
  if (relevant.length > 0 && relevant.every((i) => ["delivered", "returned"].includes(i.fulfillmentStatus))) {
    return "completed";
  }
  if (myItems.some((i) => (i.fulfillmentStatus || "new") === "new")) return "new";
  if (myItems.some((i) => i.fulfillmentStatus === "preparing")) return "preparing";
  return "shipped";
}

const SALES_TABS = [
  { key: "all", label: "All" },
  { key: "new", label: "New" },
  { key: "preparing", label: "Preparing" },
  { key: "shipped", label: "Shipped" },
  { key: "completed", label: "Completed" },
  { key: "cancelled", label: "Cancelled" },
];

function Tag({ children, color }) {
  return (
    <span
      className="inline-block px-2 py-0.5 rounded-full text-xs font-medium"
      style={{ backgroundColor: color + "20", color }}
    >
      {children}
    </span>
  );
}

function StarRating({ value, onChange }) {
  return (
    <div className="flex items-center gap-1">
      {[1, 2, 3, 4, 5].map((n) => (
        <button
          key={n}
          type="button"
          onClick={() => onChange(n)}
          className="text-xl leading-none"
          style={{ color: n <= value ? "#E8A94D" : "#DDD8CC" }}
          aria-label={`${n} star${n > 1 ? "s" : ""}`}
        >
          ★
        </button>
      ))}
    </div>
  );
}

function StarDisplay({ value, size = "text-sm" }) {
  return (
    <span className={size} style={{ color: "#E8A94D", letterSpacing: "1px" }}>
      {"★".repeat(Math.round(value))}
      <span style={{ color: "#DDD8CC" }}>{"★".repeat(5 - Math.round(value))}</span>
    </span>
  );
}

const TRACKING_STEPS = [
  { status: "new", label: "Order placed" },
  { status: "shipped", label: "Shipped" },
  { status: "delivered", label: "Delivered" },
];

function TrackingTimeline({ item, orderCreatedAt, ink, slate, sage, berry }) {
  const history = item.statusHistory && item.statusHistory.length > 0
    ? item.statusHistory
    : [{ status: "new", at: orderCreatedAt }];
  return (
    <div>
      <div className="text-xs font-medium mb-2" style={{ color: ink }}>Order status history</div>
      <div className="space-y-0">
      {history.map((event, idx) => {
        const isProblem = /cancel|return|failed|dispute_opened/.test(event.status);
        const isPending = /estimate|location|processing|sent|proof/.test(event.status);
        const color = isProblem ? berry : isPending ? "#E8A94D" : sage;
        const start = event.details?.start ? formatDeliveryDate(event.details.start) : "";
        const end = event.details?.end ? formatDeliveryDate(event.details.end) : "";
        return (
          <div key={`${event.status}-${event.at}-${idx}`} className="flex gap-2 items-start text-xs">
            <div className="flex flex-col items-center">
              <span className="w-2.5 h-2.5 rounded-full mt-1" style={{ backgroundColor: color }} />
              {idx < history.length - 1 && <span className="w-0.5 h-7" style={{ backgroundColor: color + "50" }} />}
            </div>
            <div className="pb-2 min-w-0">
              <div className="font-medium" style={{ color: isProblem ? berry : ink }}>{event.label || FULFILLMENT_LABEL[event.status] || "Order updated"}</div>
              <div style={{ color: slate }}>{new Date(event.at || orderCreatedAt).toLocaleString()}</div>
              {start && <div style={{ color: slate }}>{end && end !== start ? `${start} – ${end}` : start}</div>}
            </div>
          </div>
        );
      })}
      </div>
    </div>
  );
}

function RefundProgress({ order, ink, slate, sage, berry, marigold, canvas }) {
  const status = order.paymentStatus === "refunded" ? "processed" : String(order.refundStatus || "").toLowerCase();
  const isComplete = status === "processed";
  const isFailed = status === "failed";
  const needsAttention = ["request_unknown", "needs-attention", "needs_attention"].includes(status);
  const submittedToPaystack = !!order.paystackRefundId || !["", "requesting"].includes(status);
  const isProcessing = submittedToPaystack && !isComplete && !isFailed;
  const latestAt = order.refundUpdatedAt || order.refundedAt || order.refundRequestedAt;
  const steps = [
    { label: "Cancellation submitted", done: !!order.refundRequestedAt || !!status, at: order.refundRequestedAt },
    { label: order.refundType === "buyer_cancellation" ? "2% fee and refund calculated" : "Refund amount calculated", done: Number(order.refundAmount || 0) > 0 },
    { label: "Refund sent to Paystack", done: submittedToPaystack },
    { label: needsAttention ? "Paystack needs attention" : "Paystack processing", done: isProcessing || isComplete, warning: needsAttention },
    { label: isFailed ? "Refund failed — action required" : "Refund completed", done: isComplete || isFailed, failed: isFailed, at: order.refundedAt },
  ];

  return (
    <div className="mt-4 p-4 rounded-xl border" style={{ borderColor: isFailed ? berry : isComplete ? sage : marigold, backgroundColor: canvas }}>
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="font-semibold text-sm" style={{ color: ink }}>Refund progress</div>
        <Tag color={isFailed ? berry : isComplete ? sage : marigold}>
          {isFailed ? "Action required" : isComplete ? "Completed" : needsAttention ? "Needs attention" : "In progress"}
        </Tag>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mt-3 text-xs">
        <div><span style={{ color: slate }}>Original total</span><div className="font-semibold" style={{ color: ink }}>{formatMoney(order.total, order.currency)}</div></div>
        <div><span style={{ color: slate }}>Cancellation fee</span><div className="font-semibold" style={{ color: order.cancellationFee > 0 ? berry : ink }}>{formatMoney(order.cancellationFee || 0, order.currency)}</div></div>
        <div><span style={{ color: slate }}>Refund amount</span><div className="font-semibold" style={{ color: sage }}>{formatMoney(order.refundAmount || 0, order.currency)}</div></div>
      </div>

      <div className="mt-4 space-y-2">
        {steps.map((step, index) => (
          <div key={step.label} className="flex gap-2 items-start text-xs">
            <div className="flex flex-col items-center">
              <span className="w-3 h-3 rounded-full mt-0.5" style={{ backgroundColor: step.failed ? berry : step.warning ? marigold : step.done ? sage : "#DDD8CC" }} />
              {index < steps.length - 1 && <span className="w-0.5 h-5" style={{ backgroundColor: step.done ? sage + "60" : "#DDD8CC" }} />}
            </div>
            <div style={{ color: step.failed ? berry : step.warning ? marigold : step.done ? ink : slate }}>
              <span className={step.done ? "font-medium" : ""}>{step.label}</span>
              {step.at && <span style={{ color: slate }}> · {new Date(step.at).toLocaleString()}</span>}
            </div>
          </div>
        ))}
      </div>

      {latestAt && <div className="text-xs mt-3" style={{ color: slate }}>Latest update: {new Date(latestAt).toLocaleString()}</div>}
      {order.paystackRefundId && <div className="text-xs mt-1 break-all" style={{ color: slate }}>Paystack refund reference: <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: ink }}>{order.paystackRefundId}</span></div>}
      {order.refundFailureReason && <div className="text-xs mt-2 p-2 rounded-lg" style={{ color: berry, backgroundColor: "white" }}>{order.refundFailureReason}</div>}
      {!isFailed && (
        <div className="text-xs mt-3" style={{ color: slate }}>
          {isComplete
            ? "Paystack has completed the refund. Your bank may take additional time to display the credit."
            : "Stallyard will update this timeline when Paystack confirms the refund. Do not submit another cancellation request."}
        </div>
      )}
    </div>
  );
}

function PriceTagCard({ listing, onOpen, onAddToCart, rating, isSaved, onToggleWatchlist, onOpenStorefront, now, onVacation }) {
  const color = CATEGORY_COLOR[listing.category] || SLATE;
  const isAuction = listing.listingType === "auction";
  const timeLeft = isAuction ? formatTimeRemaining(listing.auctionEndTime, now || Date.now()) : null;
  const auctionEnded = isAuction && !timeLeft;
  return (
    <div
      className="text-left relative bg-white rounded-r-2xl shadow-sm hover:shadow-md hover:-translate-y-1 transition-all duration-200 motion-reduce:transform-none overflow-visible w-full"
      style={{ borderLeft: `6px solid ${color}` }}
    >
      {/* punched hole */}
      <div
        className="absolute -left-[15px] top-4 w-5 h-5 rounded-full border-2 z-10"
        style={{ backgroundColor: CANVAS, borderColor: color }}
      />
      {listing.isFeatured && (
        <div
          className="absolute -top-2 right-3 px-2 py-0.5 rounded-full text-[11px] font-semibold z-10 shadow-sm"
          style={{ backgroundColor: MARIGOLD, color: INK }}
        >
          Featured
        </div>
      )}
      {isAuction && !listing.isFeatured && (
        <div
          className="absolute -top-2 right-3 px-2 py-0.5 rounded-full text-[11px] font-semibold z-10 shadow-sm text-white"
          style={{ backgroundColor: "#3B6E8F" }}
        >
          🔨 Auction
        </div>
      )}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onToggleWatchlist(listing.id);
        }}
        className="absolute top-2 left-3 z-10 w-8 h-8 rounded-full flex items-center justify-center bg-white/90 shadow-sm"
        aria-label={isSaved ? "Remove from watchlist" : "Save to watchlist"}
      >
        <Heart
          size={16}
          style={{ color: isSaved ? BERRY : SLATE }}
          fill={isSaved ? BERRY : "none"}
        />
      </button>
      <button onClick={() => onOpen(listing)} className="text-left w-full">
        {listing.images && listing.images.length > 0 ? (
          <div className="relative">
            <img
              src={listing.images[0]}
              srcSet={responsiveListingSrcSet(listing.images[0])}
              sizes="(max-width: 640px) calc(50vw - 24px), (max-width: 1024px) 33vw, 320px"
              alt={listing.title}
              width="640"
              height="360"
              loading="lazy"
              decoding="async"
              className="w-full h-36 object-cover rounded-tr-2xl"
            />
            <span
              className="absolute top-2 right-2 px-2 py-0.5 rounded-full text-sm font-semibold bg-white/90"
              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
            >
              {formatMoney(listing.price, listing.currency)}
            </span>
            {listing.images.length > 1 && (
              <span
                className="absolute bottom-2 right-2 px-1.5 py-0.5 rounded text-[11px] font-medium text-white"
                style={{ backgroundColor: "rgba(27,36,48,0.75)" }}
              >
                +{listing.images.length - 1} more
              </span>
            )}
          </div>
        ) : null}
        <div className="p-5 pl-6">
          {!(listing.images && listing.images.length > 0) && (
            <div className="flex items-start justify-between gap-2">
              <div className="text-3xl leading-none">{listing.emoji}</div>
              <div
                className="font-semibold text-lg"
                style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
              >
                {formatMoney(listing.price, listing.currency)}
              </div>
            </div>
          )}
          <h3
            className="mt-3 text-lg leading-snug"
            style={{ fontFamily: "'DM Serif Display', serif", color: INK }}
          >
            {listing.title}
          </h3>
          <p className="mt-1 text-sm line-clamp-2" style={{ color: SLATE }}>
            {listing.description}
          </p>
          {isAuction && (
            <p className="mt-1 text-xs font-medium" style={{ color: "#3B6E8F" }}>
              Current bid: {formatMoney(listing.price, listing.currency)}
              {(listing.bidHistory || []).length > 0 ? ` (${listing.bidHistory.length} bid${listing.bidHistory.length !== 1 ? "s" : ""})` : " (no bids yet)"}
              {" · "}
              {auctionEnded ? "Ended" : timeLeft}
            </p>
          )}
          {listing.category === "Auto Parts" && (listing.fitMake || listing.fitModel) && (
            <p className="mt-1 text-xs font-medium" style={{ color: CATEGORY_COLOR["Auto Parts"] }}>
              Fits: {[listing.fitMake, listing.fitModel, listing.fitYear].filter(Boolean).join(" ")}
            </p>
          )}
          <p className="mt-1 text-xs" style={{ color: SLATE }}>
            {listing.shippingFee ? `+ ${formatMoney(listing.shippingFee, listing.currency)} shipping` : "Free shipping"}
          </p>
        </div>
      </button>
      <div className="px-5 pl-6 pb-4">
        <div className="mb-1 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Tag color={color}>{listing.category}</Tag>
            {listing.condition && listing.condition !== "New" && (
              <Tag color={CONDITION_COLOR[listing.condition] || SLATE}>{listing.condition}</Tag>
            )}
          </div>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onOpenStorefront(listing.ownerUsername);
            }}
            className="text-xs flex items-center gap-1 underline"
            style={{ color: SLATE }}
          >
            {rating && <StarDisplay value={rating.avg} size="text-xs" />}
            by {listing.sellerName}
          </button>
        </div>
        {onVacation && (
          <p className="text-xs mb-2" style={{ color: MARIGOLD }}>
            🌴 Seller on vacation
            {onVacation.returnDate
              ? ` until ${new Date(onVacation.returnDate).toLocaleDateString(undefined, { month: "short", day: "numeric" })}`
              : ""}
          </p>
        )}
        {isAuction ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onOpen(listing);
            }}
            className="w-full py-2 rounded-lg text-sm font-medium border flex items-center justify-center gap-2"
            style={{ borderColor: color, color }}
          >
            {auctionEnded ? "View auction" : "Place a bid"}
          </button>
        ) : (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onAddToCart(listing);
            }}
            className="w-full py-2 rounded-lg text-sm font-medium border flex items-center justify-center gap-2"
            style={{ borderColor: color, color }}
          >
            <ShoppingBag size={14} />
            Add to cart
          </button>
        )}
      </div>
    </div>
  );
}

function StallyardErrorScreen({ onRetry }) {
  return (
    <div
      className="min-h-screen w-full flex items-center justify-center px-6"
      style={{ backgroundColor: CANVAS, fontFamily: "'Work Sans', sans-serif" }}
    >
      <div className="w-full max-w-md text-center bg-white rounded-2xl px-8 py-10 shadow-sm border" style={{ borderColor: "#E8E1D5" }}>
        <div
          className="w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-5"
          style={{ backgroundColor: MARIGOLD }}
          aria-label="Stallyard emblem"
        >
          <span style={{ fontFamily: "'DM Serif Display', serif", color: INK, fontSize: "30px", lineHeight: 1 }}>S</span>
        </div>
        <div className="text-sm font-semibold tracking-wide mb-2" style={{ color: BERRY }}>STALLYARD</div>
        <h1 className="text-2xl font-semibold mb-2" style={{ color: INK }}>Something went wrong</h1>
        <p className="text-sm mb-6" style={{ color: SLATE }}>Please try again in a moment.</p>
        <button
          onClick={onRetry}
          className="px-5 py-2.5 rounded-lg font-semibold"
          style={{ backgroundColor: MARIGOLD, color: INK }}
        >
          Try again
        </button>
      </div>
    </div>
  );
}

function CasualSellerVerificationModal({ onClose, onApproved, authFetch, showToast }) {
  const videoRef = useRef(null);
  const streamRef = useRef(null);
  const detectorRef = useRef(null);
  const neutralFaceSizeRef = useRef(null);
  const [cameraReady, setCameraReady] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ legalName: "", dateOfBirth: "", consent: false });
  const [captures, setCaptures] = useState({ liveSelfie: "", holdingIdSelfie: "", challengeFrames: [] });
  const [faceChecks, setFaceChecks] = useState([]);
  const [faceDetectionSupported, setFaceDetectionSupported] = useState(false);
  const [challenges, setChallenges] = useState([]);
  const [challengeToken, setChallengeToken] = useState("");
  const [challengeLoading, setChallengeLoading] = useState(true);
  const [awsLiveness, setAwsLiveness] = useState(null);
  const [awsLivenessVerified, setAwsLivenessVerified] = useState(false);
  const [rekognitionVerificationToken, setRekognitionVerificationToken] = useState("");

  const labels = {
    blink: "Blink slowly, then look at the camera",
    turn_left: "Turn your head to the left",
    turn_right: "Turn your head to the right",
    smile: "Smile while looking at the camera",
    move_closer: "Move your face slightly closer",
  };

  useEffect(() => () => {
    if (streamRef.current) streamRef.current.getTracks().forEach((track) => track.stop());
    if (detectorRef.current?.close) detectorRef.current.close();
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [challengeResponse, awsResponse] = await Promise.all([
          authFetch(`${BACKEND_URL}/casual-seller/challenge`, { method: "POST" }),
          authFetch(`${BACKEND_URL}/casual-seller/rekognition/session`, { method: "POST" }),
        ]);
        const [data, awsData] = await Promise.all([challengeResponse.json(), awsResponse.json()]);
        if (!challengeResponse.ok) throw new Error(data.error || "Couldn't start secure verification");
        if (!awsResponse.ok) throw new Error(awsData.error || "Couldn't start AWS face verification");
        if (!cancelled) {
          setChallenges(data.challenges || []); setChallengeToken(data.token || "");
          setAwsLiveness(awsData);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Couldn't start secure verification");
      } finally {
        if (!cancelled) setChallengeLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const completeAwsLiveness = async () => {
    const response = await authFetch(`${BACKEND_URL}/casual-seller/rekognition/complete`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sessionId: awsLiveness.sessionId }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "AWS could not verify liveness");
    setAwsLivenessVerified(true);
    setRekognitionVerificationToken(data.verificationToken || "");
    showToast(`Secure liveness verified (${Math.round(Number(data.confidence || 0))}%)`);
  };

  const initializeFaceDetector = async () => {
    const vision = await import(/* @vite-ignore */ "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.35/+esm");
    const files = await vision.FilesetResolver.forVisionTasks("https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.35/wasm");
    const detector = await vision.FaceLandmarker.createFromOptions(files, {
      baseOptions: { modelAssetPath: "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task" },
      runningMode: "IMAGE", numFaces: 2, outputFaceBlendshapes: true,
    });
    return detector;
  };

  const startCamera = async () => {
    setError("");
    if (!navigator.mediaDevices?.getUserMedia) {
      setError("This browser cannot securely open the camera. Use an updated phone browser.");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 1280 } }, audio: false });
      streamRef.current = stream;
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      detectorRef.current = await initializeFaceDetector();
      setCameraReady(true);
      setFaceDetectionSupported(true);
    } catch {
      if (streamRef.current) streamRef.current.getTracks().forEach((track) => track.stop());
      setError("The secure camera or on-device face checker could not start. Check camera permission and your connection, then try again.");
    }
  };

  const captureCamera = async (kind, requestedChallenge = null) => {
    const video = videoRef.current;
    if (!video || !cameraReady || !video.videoWidth) return;
    const canvas = document.createElement("canvas");
    const size = Math.min(video.videoWidth, video.videoHeight);
    const sx = Math.floor((video.videoWidth - size) / 2), sy = Math.floor((video.videoHeight - size) / 2);
    canvas.width = 900; canvas.height = 900;
    canvas.getContext("2d").drawImage(video, sx, sy, size, size, 0, 0, 900, 900);
    const dataUrl = canvas.toDataURL("image/jpeg", 0.82);
    let facePresent = false;
    if (detectorRef.current) {
      try {
        const result = detectorRef.current.detect(canvas);
        facePresent = result.faceLandmarks?.length === 1;
        if (facePresent) {
          const landmarks = result.faceLandmarks[0];
          const xs = landmarks.map((point) => point.x), ys = landmarks.map((point) => point.y);
          const faceWidth = Math.max(...xs) - Math.min(...xs), faceHeight = Math.max(...ys) - Math.min(...ys);
          if (kind === "live") neutralFaceSizeRef.current = faceWidth * faceHeight;
          if (requestedChallenge) {
            const scores = Object.fromEntries((result.faceBlendshapes?.[0]?.categories || []).map((item) => [item.categoryName, item.score]));
            const noseRatio = (landmarks[1].x - Math.min(...xs)) / Math.max(faceWidth, 0.001);
            const challengePassed = requestedChallenge === "blink" ? Math.max(scores.eyeBlinkLeft || 0, scores.eyeBlinkRight || 0) > 0.45
              : requestedChallenge === "smile" ? Math.max(scores.mouthSmileLeft || 0, scores.mouthSmileRight || 0) > 0.45
              : requestedChallenge === "turn_left" || requestedChallenge === "turn_right" ? Math.abs(noseRatio - 0.5) > 0.06
              : requestedChallenge === "move_closer" ? neutralFaceSizeRef.current && faceWidth * faceHeight > neutralFaceSizeRef.current * 1.18
              : false;
            if (!challengePassed) { setError(`The “${labels[requestedChallenge]}” movement was not detected. Hold the position and capture again.`); return; }
          }
        }
      } catch { facePresent = false; }
      if (!facePresent) { setError("Exactly one clear face must be visible. Adjust the lighting and try again."); return; }
    }
    setFaceChecks((current) => [...current, facePresent]);
    setError("");
    if (kind === "live") setCaptures((current) => ({ ...current, liveSelfie: dataUrl }));
    else if (kind === "holding") setCaptures((current) => ({ ...current, holdingIdSelfie: dataUrl }));
    else setCaptures((current) => ({ ...current, challengeFrames: [...current.challengeFrames, dataUrl].slice(0, 3) }));
  };

  const submit = async () => {
    setError("");
    if (!awsLivenessVerified || !rekognitionVerificationToken) { setError("Complete the secure AWS face-liveness check first."); return; }
    if (!faceDetectionSupported) { setError("Automatic face detection is unavailable on this browser. Use an updated supported phone or browser so Stallyard does not approve an unverified person."); return; }
    if (!form.legalName.trim() || !form.dateOfBirth) { setError("Enter your legal name and date of birth."); return; }
    if (!captures.liveSelfie || !captures.holdingIdSelfie || captures.challengeFrames.length !== 3) { setError("Complete the live selfie, all three challenges, and the selfie holding your ID."); return; }
    if (!form.consent) { setError("You must accept the identity-record consent before submitting."); return; }
    setSubmitting(true);
    try {
      const response = await authFetch(`${BACKEND_URL}/casual-seller/apply`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, ...captures, challenges, challengeToken, faceDetectionSupported, faceChecks, rekognitionVerificationToken }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Verification could not be completed");
      onApproved(data);
      showToast(data.status === "approved" ? "Identity verified — you can now publish up to ₦500,000 in active listings" : "Verification needs attention — review the result and try again");
      onClose();
    } catch (err) { setError(err.message); }
    finally { setSubmitting(false); }
  };

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center p-4 overflow-y-auto" style={{ backgroundColor: "rgba(27,36,48,.72)" }} onClick={onClose}>
      <div className="w-full max-w-3xl rounded-2xl p-5 my-6" style={{ backgroundColor: CANVAS }} onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 mb-4">
          <div><h2 className="text-2xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Automatic casual-seller verification</h2><p className="text-sm" style={{ color: SLATE }}>Verify once to publish up to ₦500,000 in combined active listings.</p></div>
          <button onClick={onClose} aria-label="Close"><X size={22} /></button>
        </div>
        <div className="mb-4 p-3 rounded-lg border text-xs leading-5" style={{ borderColor: MARIGOLD, backgroundColor: "#FFF8E8", color: SLATE }}>
          <strong style={{ color: INK }}>Identity-check attempt limit:</strong> You may start up to 3 AWS face-liveness checks in a rolling 24-hour period. Closing, restarting or abandoning a started check still uses an attempt.
          {awsLiveness && <span className="block mt-1 font-medium" style={{ color: INK }}>{Number(awsLiveness.remainingAttempts || 0)} attempt{Number(awsLiveness.remainingAttempts || 0) === 1 ? "" : "s"} remaining after this session.</span>}
        </div>
        {!awsLivenessVerified && awsLiveness && (
          <div className="mb-5 rounded-xl overflow-hidden border bg-white" style={{ borderColor: SAGE }}>
            <Suspense fallback={<div className="p-8 text-center text-sm" style={{ color: SLATE }}>Loading secure face verification…</div>}>
              <FaceLivenessDetectorCore
                sessionId={awsLiveness.sessionId}
                region={awsLiveness.region}
                config={{ credentialProvider: async () => ({
                  accessKeyId: awsLiveness.credentials.accessKeyId,
                  secretAccessKey: awsLiveness.credentials.secretAccessKey,
                  sessionToken: awsLiveness.credentials.sessionToken,
                  expiration: awsLiveness.credentials.expiration ? new Date(awsLiveness.credentials.expiration) : undefined,
                }) }}
                onAnalysisComplete={completeAwsLiveness}
                onError={(livenessError) => setError(livenessError?.error?.message || livenessError?.message || "AWS face-liveness verification failed")}
                onUserCancel={onClose}
              />
            </Suspense>
          </div>
        )}
        {awsLivenessVerified && <p className="mb-4 text-sm font-medium" style={{ color: SAGE }}>✓ AWS face-liveness verification passed</p>}
        <div className="grid md:grid-cols-2 gap-5">
          <div className="space-y-3">
            <input className="w-full px-3 py-2 rounded-lg border" placeholder="Legal name exactly as shown on ID" value={form.legalName} onChange={(e) => setForm({ ...form, legalName: e.target.value })} />
            <label className="block text-xs" style={{ color: SLATE }}>Date of birth<input type="date" className="block w-full mt-1 px-3 py-2 rounded-lg border" value={form.dateOfBirth} onChange={(e) => setForm({ ...form, dateOfBirth: e.target.value })} /></label>
            <div className="p-3 rounded-lg border text-xs" style={{ borderColor: SAGE, backgroundColor: "#EDF4EE", color: SLATE }}>
              You do not need to enter an ID number or upload separate ID photographs for Casual Seller verification. You will only take a selfie while holding your identification.
            </div>
          </div>
          <div>
            <div className="aspect-square rounded-xl overflow-hidden bg-black mb-2"><video ref={videoRef} muted playsInline className="w-full h-full object-cover" /></div>
            {!cameraReady ? <button disabled={challengeLoading || !challengeToken || !awsLivenessVerified} onClick={startCamera} className="w-full py-2 rounded-lg font-medium disabled:opacity-50" style={{ backgroundColor: MARIGOLD, color: INK }}>{challengeLoading ? "Preparing secure challenge…" : !awsLivenessVerified ? "Complete AWS liveness first" : "Open secure camera"}</button> : (
              <div className="space-y-2 text-sm">
                <button onClick={() => captureCamera("live")} className="w-full py-2 rounded-lg border">{captures.liveSelfie ? "✓ Retake neutral live selfie" : "Capture neutral live selfie"}</button>
                {challenges.map((challenge, index) => <button key={challenge} disabled={captures.challengeFrames.length !== index} onClick={() => captureCamera("challenge", challenge)} className="w-full py-2 px-2 rounded-lg border disabled:opacity-40 text-left">{captures.challengeFrames[index] ? "✓ " : `${index + 1}. `}{labels[challenge]}</button>)}
                <button onClick={() => captureCamera("holding")} className="w-full py-2 rounded-lg border">{captures.holdingIdSelfie ? "✓ Retake selfie holding ID" : "Hold your ID beside your face and capture"}</button>
              </div>
            )}
          </div>
        </div>
        <label className="flex gap-2 mt-5 text-xs" style={{ color: SLATE }}><input type="checkbox" checked={form.consent} onChange={(e) => setForm({ ...form, consent: e.target.checked })} /><span>I consent to Stallyard collecting and securely retaining my identity images and verification results for fraud prevention, account security, seller accountability, transaction investigations, and legal recordkeeping. They may be accessed only by authorized Stallyard verification personnel.</span></label>
        {error && <p className="text-sm mt-3" style={{ color: BERRY }}>{error}</p>}
        <button disabled={submitting} onClick={submit} className="w-full mt-4 py-3 rounded-lg font-semibold disabled:opacity-50" style={{ backgroundColor: MARIGOLD, color: INK }}>{submitting ? "Securely checking and saving…" : "Submit for automatic verification"}</button>
      </div>
    </div>
  );
}

function LiveDeliveryPhotoCamera({ onSave, onClose, busy }) {
  const videoRef = useRef(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [photo, setPhoto] = useState(null);
  const [facing, setFacing] = useState("environment");
  useEffect(() => {
    let cancelled = false;
    let stream;
    setReady(false);
    setError("");
    (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia) throw new Error("Camera unavailable");
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: facing }, width: { ideal: 1400 } }, audio: false });
        if (cancelled) { stream.getTracks().forEach((track) => track.stop()); return; }
        const video = videoRef.current;
        video.srcObject = stream;
        await video.play();
        if (!cancelled) setReady(true);
      } catch {
        stream?.getTracks().forEach((track) => track.stop());
        if (!cancelled) setError("Camera access is required. Allow camera access in your browser settings, then reopen this camera. Saved pictures cannot be used.");
      }
    })();
    return () => { cancelled = true; stream?.getTracks().forEach((track) => track.stop()); };
  }, [facing]);
  const capture = () => {
    const video = videoRef.current;
    if (!ready || !video?.videoWidth || !video.videoHeight || video.readyState < 2) return;
    try {
      const scale = Math.min(1, 1400 / Math.max(video.videoWidth, video.videoHeight));
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(video.videoWidth * scale);
      canvas.height = Math.round(video.videoHeight * scale);
      canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
      setPhoto(canvas.toDataURL("image/jpeg", 0.85));
    } catch { setError("Couldn't capture the photo. Please try again."); }
  };
  return (
    <div className="fixed inset-0 z-[110] flex items-center justify-center p-4" style={{ backgroundColor: "rgba(10,15,22,.86)" }}>
      <div role="dialog" aria-modal="true" aria-label="Take delivery photo" className="w-full max-w-lg rounded-2xl bg-white p-4 shadow-xl">
        <div className="flex justify-between gap-3 mb-3">
          <div><h3 className="text-lg font-semibold">Take delivery photo</h3><p className="text-xs mt-1">Take a fresh picture of the handoff. Saved pictures cannot be selected.</p></div>
          <button type="button" disabled={busy} onClick={onClose} aria-label="Close delivery camera"><X size={22} /></button>
        </div>
        <video ref={videoRef} autoPlay muted playsInline className={photo ? "hidden" : "w-full rounded-xl bg-black aspect-video object-contain"} />
        {photo && <img src={photo} alt="Review captured delivery photo" className="w-full rounded-xl" />}
        {error && <p role="alert" className="text-sm mt-3" style={{ color: BERRY }}>{error}</p>}
        {!photo && !error && !ready && <p className="text-sm mt-2">Starting live camera…</p>}
        <div className="flex gap-2 mt-3">
          {photo ? <>
            <button type="button" disabled={busy} onClick={() => setPhoto(null)} className="px-4 py-2 rounded-lg border disabled:opacity-50">Retake</button>
            <button type="button" disabled={busy} onClick={() => onSave(photo)} className="px-4 py-2 rounded-lg disabled:opacity-50" style={{ backgroundColor: MARIGOLD }}>{busy ? "Saving…" : "Use photo"}</button>
          </> : <>
            <button type="button" disabled={!ready || !!error} onClick={capture} className="px-4 py-2 rounded-lg disabled:opacity-50" style={{ backgroundColor: MARIGOLD }}>Take photo</button>
            <button type="button" disabled={!ready} onClick={() => setFacing((value) => value === "environment" ? "user" : "environment")} className="px-4 py-2 rounded-lg border disabled:opacity-50">Switch camera</button>
          </>}
        </div>
      </div>
    </div>
  );
}

function MarketplaceStallyard() {
  useFonts();
  const [fatalServerError, setFatalServerError] = useState(false);
  useEffect(() => {
    const handleServerError = () => setFatalServerError(true);
    window.addEventListener("stallyard:server-error", handleServerError);
    return () => window.removeEventListener("stallyard:server-error", handleServerError);
  }, []);
  const [route, setRoute] = useMarketplaceRouting(isAdminHost());
  const view = route.view;
  const setView = (value) => setRoute((previous) => ({ ...previous, listingId: null, cart: false, view: value === "login" ? "signin" : typeof value === "function" ? value(previous.view) : value }));
  const setRouteField = (key, value) => setRoute((previous) => ({ ...previous, [key]: typeof value === "function" ? value(previous[key]) : value }));

  const [adminLoginMode, setAdminLoginMode] = useState(() => isAdminHost());
  const [adminLoginForm, setAdminLoginForm] = useState({ username: "", password: "" });
  const [adminLoginStep, setAdminLoginStep] = useState("credentials"); // "credentials" | "code" | "code-email" | "new-password"
  const [adminLoginCode, setAdminLoginCode] = useState("");
  const [adminLoginPendingUserId, setAdminLoginPendingUserId] = useState(null);
  const [adminTempPasswordChangeToken, setAdminTempPasswordChangeToken] = useState("");
  const [adminTempNewPasswordForm, setAdminTempNewPasswordForm] = useState({ password: "", confirm: "" });
  const [adminLoginError, setAdminLoginError] = useState("");
  const [adminLoginSubmitting, setAdminLoginSubmitting] = useState(false);
  const [authReturnView, setAuthReturnView] = useState("browse");
  const [adminTab, setAdminTab] = useState(() => {
    if (typeof window === "undefined" || !isAdminHost()) return "overview";
    return window.sessionStorage.getItem(ADMIN_TAB_STORAGE_KEY) || "overview";
  });
  // Keep the admin unlock only for this browser tab/session. A normal page
  // refresh restores the remaining unlock window, but closing the tab/browser
  // clears sessionStorage and the admin must complete the 3-step login again.
  const [adminUnlockedUntil, setAdminUnlockedUntil] = useState(() => {
    if (typeof window === "undefined" || !isAdminHost()) return null;
    const raw = window.sessionStorage.getItem(ADMIN_SESSION_STORAGE_KEY);
    const expiresAt = Number(raw);
    if (Number.isFinite(expiresAt) && expiresAt > Date.now()) return expiresAt;
    window.sessionStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
    return null;
  });
  useEffect(() => {
    if (typeof window === "undefined" || !isAdminHost()) return;
    try {
      window.sessionStorage.setItem(ADMIN_TAB_STORAGE_KEY, adminTab);
    } catch {
      // Non-critical: if sessionStorage is unavailable, the tab simply resets on refresh.
    }
  }, [adminTab]);

  const [adminReauthStep, setAdminReauthStep] = useState(null); // null | "password" | "code" | "code-email"
  const [adminReauthPassword, setAdminReauthPassword] = useState("");
  const [adminReauthCode, setAdminReauthCode] = useState("");
  const [adminReauthSubmitting, setAdminReauthSubmitting] = useState(false);
  const [adminReauthError, setAdminReauthError] = useState("");
  const [addMemberOpen, setAddMemberOpen] = useState(false);
  const [expandedDocsUsername, setExpandedDocsUsername] = useState(null);
  const [adminEditContext, setAdminEditContext] = useState(false);
  const [addMemberForm, setAddMemberForm] = useState({
    firstName: "",
    lastName: "",
    otherName: "",
    displayName: "",
    officeLocation: "",
    username: "",
    email: "",
    phone: "",
    password: "",
  });
  const [contentTab, setContentTab] = useState("banners");
  const [bannerForm, setBannerForm] = useState({
    message: "",
    tone: "info",
    mediaType: "none",
    imageUrl: "",
    videoUrl: "",
  });
  const [bannerImageUploading, setBannerImageUploading] = useState(false);
  const [authImageUploading, setAuthImageUploading] = useState(false);
  const [articleModalOpen, setArticleModalOpen] = useState(false);
  const [articleForm, setArticleForm] = useState({ title: "", body: "" });
  const [editingArticleId, setEditingArticleId] = useState(null);
  const [faqForm, setFaqForm] = useState({ question: "", answer: "" });
  const [editingFaqId, setEditingFaqId] = useState(null);
  const [openFaqId, setOpenFaqId] = useState(null);
  const [listings, setListings] = useState([]);
  const [membersLoaded, setMembersLoaded] = useState(false);
  // True only once the saved session (if any) has actually been read back
  // from storage — distinct from membersLoaded, which flips true slightly
  // earlier in the same startup sequence, before currentUser is resolved.
  // Anything that redirects based on "is someone logged in" needs to wait
  // for this, not just membersLoaded, or it acts on a stale null.
  const [sessionChecked, setSessionChecked] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const search = route.search;
  const setSearch = (value) => setRouteField("search", value);
  const categoryFilter = route.category;
  const setCategoryFilter = (value) => setRouteField("category", value);
  const subcategoryFilter = route.subcategory;
  const setSubcategoryFilter = (value) => setRouteField("subcategory", value);
  const [categoriesMenuOpen, setCategoriesMenuOpen] = useState(false);
  const categoriesMenuRef = useRef(null);
  const conditionFilter = route.condition;
  const setConditionFilter = (value) => setRouteField("condition", value);
  const sortBy = route.sort;
  const setSortBy = (value) => setRouteField("sort", value);
  const priceMin = route.priceMin;
  const setPriceMin = (value) => setRouteField("priceMin", value);
  const priceMax = route.priceMax;
  const setPriceMax = (value) => setRouteField("priceMax", value);
  const [filtersOpen, setFiltersOpen] = useState(false);
  useEffect(() => {
    if (!categoriesMenuOpen) return;
    const handleOutsideClick = (event) => {
      if (categoriesMenuRef.current && !categoriesMenuRef.current.contains(event.target)) {
        setCategoriesMenuOpen(false);
      }
    };
    const handleEscape = (event) => {
      if (event.key === "Escape") setCategoriesMenuOpen(false);
    };
    document.addEventListener("mousedown", handleOutsideClick);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
      document.removeEventListener("keydown", handleEscape);
    };
  }, [categoriesMenuOpen]);
  const [members, setMembers] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [sessionUserProfile, setSessionUserProfile] = useState(null);
  const [authToken, setAuthToken] = useState(null);
  const [authMode, setAuthMode] = useState("register");
  const [showAuthPassword, setShowAuthPassword] = useState(false);
  const [pendingPasswordReset, setPendingPasswordReset] = useState(null);
  const [resetCodeInput, setResetCodeInput] = useState("");
  const [resetError, setResetError] = useState("");
  const [resetIdentifier, setResetIdentifier] = useState("");
  const [newPasswordForm, setNewPasswordForm] = useState({ password: "", confirm: "" });
  const [authError, setAuthError] = useState("");
  const [pendingTwoFactor, setPendingTwoFactor] = useState(null);
  const [twoFactorCodeInput, setTwoFactorCodeInput] = useState("");
  const [savingTwoFactorToggle, setSavingTwoFactorToggle] = useState(false);
  // Turning 2FA ON now requires emailing + confirming a code first, tracked
  // separately from savingTwoFactorToggle (which still covers turning OFF).
  const [enable2FAStep, setEnable2FAStep] = useState("idle"); // "idle" | "code"
  const [enable2FACodeInput, setEnable2FACodeInput] = useState("");
  const [enable2FAError, setEnable2FAError] = useState("");
  const [sendingEnable2FACode, setSendingEnable2FACode] = useState(false);
  const [verifyingEnable2FACode, setVerifyingEnable2FACode] = useState(false);
  // Admin accounts use an authenticator app instead of email codes — this
  // holds the in-progress QR/secret from /admin/totp/setup until confirmed.
  const [adminTotpSetup, setAdminTotpSetup] = useState(null); // { secret, otpauthUrl, qrCodeUrl } | null
  const [adminTotpCodeInput, setAdminTotpCodeInput] = useState("");
  const [adminTotpError, setAdminTotpError] = useState("");
  const [startingAdminTotpSetup, setStartingAdminTotpSetup] = useState(false);
  const [confirmingAdminTotpSetup, setConfirmingAdminTotpSetup] = useState(false);
  const [registrationIntent, setRegistrationIntent] = useState("buyer"); // buyer | seller
  const [accountCreatedSuccess, setAccountCreatedSuccess] = useState(false);
  const [isNewAccountOnboarding, setIsNewAccountOnboarding] = useState(false);
  const [authForm, setAuthForm] = useState({
    username: "",
    password: "",
    email: "",
    phone: "",
    displayName: "",
    firstName: "",
    lastName: "",
    otherName: "",
    dateOfBirth: "",
    gender: "",
    nationality: "",
    stateOfResidence: "",
    officeLocation: "",
    country: "Nigeria",
    licenseNumber: "",
    idType: "Passport",
    idCountry: "",
    accountType: "personal",
    licensePhotos: [],
  });
  const [selectedListingCache, setSelectedListingCache] = useState(null);
  const selected = route.listingId ? listings.find((listing) => String(listing.id) === String(route.listingId)) || (String(selectedListingCache?.id) === String(route.listingId) ? selectedListingCache : null) : null;
  const setSelected = (listing) => {
    setSelectedListingCache(listing);
    setRouteField("listingId", listing?.id || null);
  };
  const [activeImg, setActiveImg] = useState(0);
  const [galleryZoomOpen, setGalleryZoomOpen] = useState(false);
  // Pinch-to-zoom state for the full-screen gallery — scale/offset are what
  // actually render; the ref below tracks in-progress touch math without
  // triggering a re-render on every finger movement.
  const [zoomScale, setZoomScale] = useState(1);
  const [zoomOffset, setZoomOffset] = useState({ x: 0, y: 0 });
  const touchState = useRef({});
  useEffect(() => {
    setZoomScale(1);
    setZoomOffset({ x: 0, y: 0 });
  }, [activeImg, galleryZoomOpen]);

  const getTouchDistance = (touches) => {
    const dx = touches[0].clientX - touches[1].clientX;
    const dy = touches[0].clientY - touches[1].clientY;
    return Math.sqrt(dx * dx + dy * dy);
  };
  const handleZoomTouchStart = (e) => {
    if (e.touches.length === 2) {
      touchState.current.pinchStartDist = getTouchDistance(e.touches);
      touchState.current.pinchStartScale = zoomScale;
    } else if (e.touches.length === 1) {
      touchState.current.startX = e.touches[0].clientX;
      touchState.current.startY = e.touches[0].clientY;
      touchState.current.panStartOffset = zoomOffset;
    }
  };
  const handleZoomTouchMove = (e) => {
    if (e.touches.length === 2 && touchState.current.pinchStartDist) {
      const dist = getTouchDistance(e.touches);
      const nextScale = Math.min(
        4,
        Math.max(1, touchState.current.pinchStartScale * (dist / touchState.current.pinchStartDist))
      );
      setZoomScale(nextScale);
    } else if (e.touches.length === 1 && zoomScale > 1 && touchState.current.startX != null) {
      const dx = e.touches[0].clientX - touchState.current.startX;
      const dy = e.touches[0].clientY - touchState.current.startY;
      setZoomOffset({
        x: touchState.current.panStartOffset.x + dx,
        y: touchState.current.panStartOffset.y + dy,
      });
    }
  };
  const handleZoomTouchEnd = (e) => {
    // Only treat this as a swipe-to-change-photo when the image isn't
    // currently zoomed in — otherwise a swipe while zoomed should just pan.
    if (zoomScale <= 1 && touchState.current.startX != null && e.changedTouches.length === 1 && selected?.images.length > 1) {
      const deltaX = e.changedTouches[0].clientX - touchState.current.startX;
      if (Math.abs(deltaX) > 40) {
        if (deltaX < 0) setActiveImg((i) => (i < selected.images.length - 1 ? i + 1 : 0));
        else setActiveImg((i) => (i > 0 ? i - 1 : selected.images.length - 1));
      }
    }
    touchState.current = {};
  };
  const [toast, setToast] = useState("");
  const [editingId, setEditingId] = useState(null);
  const [cart, setCart] = useState([]);
  // Most-recently-viewed listing ids, newest first, capped at 12 — stored
  // the same way as cart/watchlist (local to this browser).
  const [recentlyViewedIds, setRecentlyViewedIds] = useState([]);
  const [savedCards, setSavedCards] = useState([]);
  const [savedAddresses, setSavedAddresses] = useState([]);
  const [watchlist, setWatchlist] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [notifPanelOpen, setNotifPanelOpen] = useState(false);
  const cartOpen = route.cart;
  const setCartOpen = (value) => setRouteField("cart", value);
  const [shippingForm, setShippingForm] = useState({
    fullName: "",
    phone: "",
    street: "",
    city: "",
    state: "",
    zip: "",
    country: "Nigeria",
    deliveryInstructions: "",
    preferredDeliveryTime: "",
    locationPhotos: [],
  });
  const [uploadingLocationPhotos, setUploadingLocationPhotos] = useState(false);
  const [saveShippingAddress, setSaveShippingAddress] = useState(true);
  const [shippingError, setShippingError] = useState("");
  const [confirmedOrder, setConfirmedOrder] = useState(null);
  const [checkoutSubmitting, setCheckoutSubmitting] = useState(false);
  const [checkoutVerifying, setCheckoutVerifying] = useState(false);
  const [checkoutVerifyError, setCheckoutVerifyError] = useState("");
  const [saveCardAtCheckout, setSaveCardAtCheckout] = useState(false);
  const [orders, setOrders] = useState([]);
  const buyerOrderSearch = route.orderSearch;
  const setBuyerOrderSearch = (value) => setRouteField("orderSearch", value);
  const buyerOrderStatusFilter = route.orderStatus;
  const setBuyerOrderStatusFilter = (value) => setRouteField("orderStatus", value);
  const [settings, setSettings] = useState({ commissionRate: 0.05, taxRate: 0, authImage: "" });
  const [content, setContent] = useState({ banners: [], articles: [], faqs: [] });
  const [homepageAds, setHomepageAds] = useState([
    { slot: 1, imageUrl: "", mediaType: "image", posterUrl: "", linkUrl: "" },
    { slot: 2, imageUrl: "", mediaType: "image", posterUrl: "", linkUrl: "" },
    { slot: 3, imageUrl: "", mediaType: "image", posterUrl: "", linkUrl: "" },
  ]);
  const [homepageHeroSlide, setHomepageHeroSlide] = useState(0);
  const [homepageHeroPaused, setHomepageHeroPaused] = useState(false);
  const [homepageAdUploading, setHomepageAdUploading] = useState(null);
  const [homepageAdSaving, setHomepageAdSaving] = useState(null);
  const [policies, setPolicies] = useState({
    seller_rules: "", prohibited_items: "", fees: "",
    payment_rules: "", shipping_rules: "", returns_disputes: "",
  });
  const [myTickets, setMyTickets] = useState([]);
  const [adminTickets, setAdminTickets] = useState([]);
  const activeTicketId = route.ticket;
  const setActiveTicketId = (value) => setRouteField("ticket", value);
  const [ticketMessages, setTicketMessages] = useState([]);
  const [loadingTicketMessages, setLoadingTicketMessages] = useState(false);
  const [newTicketForm, setNewTicketForm] = useState({ subject: "", message: "" });
  const [creatingTicket, setCreatingTicket] = useState(false);
  const [newTicketMessageInput, setNewTicketMessageInput] = useState("");
  const [sendingTicketMessage, setSendingTicketMessage] = useState(false);
  const [showNewTicketForm, setShowNewTicketForm] = useState(false);
  const [editingPolicyCategory, setEditingPolicyCategory] = useState(null);
  const [policyDraft, setPolicyDraft] = useState("");
  const [withdrawals, setWithdrawals] = useState([]);
  const [refundAdminFilter, setRefundAdminFilter] = useState("all");
  const [refundAdminSearch, setRefundAdminSearch] = useState("");
  const [reconciliationData, setReconciliationData] = useState(null);
  const [reconciliationLoading, setReconciliationLoading] = useState(false);
  const [reconciliationError, setReconciliationError] = useState("");
  const [reconciliationSearch, setReconciliationSearch] = useState("");
  const [reconciliationFilter, setReconciliationFilter] = useState("all");
  const [sellerPerformanceData, setSellerPerformanceData] = useState(null);
  const [sellerPerformanceLoading, setSellerPerformanceLoading] = useState(false);
  const [sellerPerformanceError, setSellerPerformanceError] = useState("");
  const [sellerPerformanceSearch, setSellerPerformanceSearch] = useState("");
  const [sellerPerformanceFilter, setSellerPerformanceFilter] = useState("all");
  const [expandedSellerPerformanceId, setExpandedSellerPerformanceId] = useState(null);
  const [buyerRiskData, setBuyerRiskData] = useState(null);
  const [buyerRiskLoading, setBuyerRiskLoading] = useState(false);
  const [buyerRiskError, setBuyerRiskError] = useState("");
  const [buyerRiskSearch, setBuyerRiskSearch] = useState("");
  const [buyerRiskFilter, setBuyerRiskFilter] = useState("all");
  const [expandedBuyerRiskId, setExpandedBuyerRiskId] = useState(null);
  const [casualSellerApplications, setCasualSellerApplications] = useState([]);
  const [casualSellerReports, setCasualSellerReports] = useState([]);
  const [verifiedSellerApplications, setVerifiedSellerApplications] = useState([]);
  const [premiumSellerApplications, setPremiumSellerApplications] = useState([]);
  const [premiumSellerReports, setPremiumSellerReports] = useState([]);
  const [verifiedSellerReports, setVerifiedSellerReports] = useState([]);
  const [casualSellerAdminLoading, setCasualSellerAdminLoading] = useState(false);
  const [selectedCasualApplication, setSelectedCasualApplication] = useState(null);
  const [casualEvidenceUrls, setCasualEvidenceUrls] = useState({});
  // Admin-wide search and filters for the high-volume operational tabs.
  const [adminListingSearch, setAdminListingSearch] = useState("");
  const [adminListingStatusFilter, setAdminListingStatusFilter] = useState("all");
  const [adminMemberSearch, setAdminMemberSearch] = useState("");
  const [adminMemberFilter, setAdminMemberFilter] = useState("all");
  const [adminOrderSearch, setAdminOrderSearch] = useState("");
  const [adminOrderStatusFilter, setAdminOrderStatusFilter] = useState("all");
  const [activeAdminOrderId, setActiveAdminOrderId] = useState(null);
  const [adminDisputeSearch, setAdminDisputeSearch] = useState("");
  const [adminDisputeStatusFilter, setAdminDisputeStatusFilter] = useState("all");
  const [adminNotesTarget, setAdminNotesTarget] = useState(null); // {entityType, entityId, label}
  const [adminNotesList, setAdminNotesList] = useState([]);
  const [adminNoteDraft, setAdminNoteDraft] = useState("");
  const [adminNotesLoading, setAdminNotesLoading] = useState(false);
  const [adminNoteSaving, setAdminNoteSaving] = useState(false);
  const [paystackChecks, setPaystackChecks] = useState({});
  const [paystackCheckingOrderId, setPaystackCheckingOrderId] = useState(null);
  const [reviews, setReviews] = useState([]);
  const [follows, setFollows] = useState([]);
  const [reviewDrafts, setReviewDrafts] = useState({});
  const [returnDrafts, setReturnDrafts] = useState({});
  const [returnTrackingDrafts, setReturnTrackingDrafts] = useState({});
  const [trackingDrafts, setTrackingDrafts] = useState({});
  const [deliveryEstimateDrafts, setDeliveryEstimateDrafts] = useState({});
  const [deliveryAssignments, setDeliveryAssignments] = useState({});
  const [deliveryAssignmentDrafts, setDeliveryAssignmentDrafts] = useState({});
  const [deliveryAssignmentSecrets, setDeliveryAssignmentSecrets] = useState({});
  const [deliveryAssignmentSavingKey, setDeliveryAssignmentSavingKey] = useState(null);
  const locationWatchersRef = useRef({});
  const locationLastSentRef = useRef({});
  const [withdrawAmount, setWithdrawAmount] = useState("");
  const [bankList, setBankList] = useState([]);
  const [bankForm, setBankForm] = useState({ bankCode: "", accountNumber: "" });
  const [bankResolution, setBankResolution] = useState({ status: "idle", accountName: "", nameMatches: false, error: "" });
  const [bankOwnerConfirmed, setBankOwnerConfirmed] = useState(false);
  const [pendingBankChange, setPendingBankChange] = useState(false);
  const [accountEmailCodeSent, setAccountEmailCodeSent] = useState(false);
  const [accountEmailCodeInput, setAccountEmailCodeInput] = useState("");
  const [verifyingAccountEmail, setVerifyingAccountEmail] = useState(false);
  const [accountPhoneInput, setAccountPhoneInput] = useState("");
  const [accountPhoneCodeSent, setAccountPhoneCodeSent] = useState(false);
  const [accountPhoneCodeInput, setAccountPhoneCodeInput] = useState("");
  const [verifyingAccountPhone, setVerifyingAccountPhone] = useState(false);
  const [bankChangeCodeInput, setBankChangeCodeInput] = useState("");
  const [changePasswordForm, setChangePasswordForm] = useState({ current: "", next: "", confirm: "" });
  const [changingPassword, setChangingPassword] = useState(false);
  const [signingOutOtherDevices, setSigningOutOtherDevices] = useState(false);
  const [suspiciousActivityMessage, setSuspiciousActivityMessage] = useState("");
  const [submittingSuspiciousReport, setSubmittingSuspiciousReport] = useState(false);
  const [accountReports, setAccountReports] = useState([]);
  const [sellerReports, setSellerReports] = useState([]);
  const [adminLocalDeliveries, setAdminLocalDeliveries] = useState([]);
  const [localDriverReports, setLocalDriverReports] = useState([]);
  const [localDeliveryLoading, setLocalDeliveryLoading] = useState(false);
  const [localDeliverySearch, setLocalDeliverySearch] = useState("");
  const [localDeliveryFilter, setLocalDeliveryFilter] = useState("all");
  const [sellerReportTarget, setSellerReportTarget] = useState(null);
  const [sellerReportReceipt, setSellerReportReceipt] = useState(null);
  const [showAllSellerReports, setShowAllSellerReports] = useState(false);
  const [sellerReportForm, setSellerReportForm] = useState({ reason: "", details: "", evidenceUrls: [] });
  const [submittingSellerReport, setSubmittingSellerReport] = useState(false);
  const [adminDisputes, setAdminDisputes] = useState([]);
  const [myDisputes, setMyDisputes] = useState([]);
  const [activeDisputeCaseId, setActiveDisputeCaseId] = useState(null);
  const [disputeAdminDrafts, setDisputeAdminDrafts] = useState({});
  const [savingDisputeCaseId, setSavingDisputeCaseId] = useState(null);
  const [auditLog, setAuditLog] = useState([]);
  const [loadingAuditLog, setLoadingAuditLog] = useState(false);
  const [auditSearch, setAuditSearch] = useState("");
  const [auditActionFilter, setAuditActionFilter] = useState("all");
  const [auditDateFilter, setAuditDateFilter] = useState("all");
  const [adminStaff, setAdminStaff] = useState([]);
  const [loadingAdminStaff, setLoadingAdminStaff] = useState(false);
  const [adminStaffError, setAdminStaffError] = useState("");
  const [adminStaffSearch, setAdminStaffSearch] = useState("");
  const [adminStaffFilter, setAdminStaffFilter] = useState("all");
  const [expandedStaffId, setExpandedStaffId] = useState(null);
  const [adminPasswordResettingId, setAdminPasswordResettingId] = useState(null);
  const [adminTempPasswordGeneratingId, setAdminTempPasswordGeneratingId] = useState(null);
  const [adminTempPasswordResult, setAdminTempPasswordResult] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const [systemHealthLoading, setSystemHealthLoading] = useState(false);
  const [systemHealthError, setSystemHealthError] = useState("");
  const [adminReportType, setAdminReportType] = useState("orders");
  const [adminReportFrom, setAdminReportFrom] = useState(() => {
    const d = new Date(); d.setDate(d.getDate() - 30); return d.toISOString().slice(0, 10);
  });
  const [adminReportTo, setAdminReportTo] = useState(() => new Date().toISOString().slice(0, 10));
  const [adminReportData, setAdminReportData] = useState(null);
  const [adminReportLoading, setAdminReportLoading] = useState(false);
  const [adminReportError, setAdminReportError] = useState("");
  const [myWarnings, setMyWarnings] = useState([]);
  const [adminWarningsTarget, setAdminWarningsTarget] = useState(null);
  const [adminWarningsList, setAdminWarningsList] = useState([]);
  const [newWarningMessage, setNewWarningMessage] = useState("");
  const [issuingWarning, setIssuingWarning] = useState(false);
  const [loginHistory, setLoginHistory] = useState(null);
  const [loadingLoginHistory, setLoadingLoginHistory] = useState(false);
  const [bankSaving, setBankSaving] = useState(false);
  const [threads, setThreads] = useState([]);
  const [messageReports, setMessageReports] = useState([]);
  const [reviewReports, setReviewReports] = useState([]);
  const [reviewResponseDrafts, setReviewResponseDrafts] = useState({});
  const [reportReviewId, setReportReviewId] = useState(null);
  const [reviewReportReasonDraft, setReviewReportReasonDraft] = useState("");
  const [sellerSalesCounts, setSellerSalesCounts] = useState({});
  const [editingStoreProfile, setEditingStoreProfile] = useState(false);
  const [storeProfileDraft, setStoreProfileDraft] = useState({ storeBio: "", storePolicies: "" });
  const [uploadingAvatar, setUploadingAvatar] = useState(false);
  const activeThreadId = route.thread;
  const setActiveThreadId = (value) => setRouteField("thread", value);
  const [activeThreadOrderId, setActiveThreadOrderId] = useState(null);
  const [messageReadState, setMessageReadState] = useState({});
  const viewingSeller = route.seller;
  const setViewingSeller = (value) => setRouteField("seller", value);
  const [bidAmount, setBidAmount] = useState("");
  const [nowTick, setNowTick] = useState(Date.now());
  const [messageInput, setMessageInput] = useState("");
  const [messageError, setMessageError] = useState("");
  const [sendingDeliveryTokenId, setSendingDeliveryTokenId] = useState(null);
  const [offerModalOpen, setOfferModalOpen] = useState(false);
  const [offerAmount, setOfferAmount] = useState("");
  const [form, setForm] = useState({
    title: "",
    description: "",
    price: "",
    category: "Handmade",
    subcategory: "",
    condition: "New",
    emoji: "📦",
    fitMake: "",
    fitModel: "",
    fitYear: "",
    images: [],
    listingType: "fixed",
    auctionDurationDays: "3",
    currency: "NGN",
    shippingFee: "0.00",
    quantity: "",
    sku: "",
    brand: "",
    state: "",
    shippingMethods: [],
    returnPolicy: "",
    vin: "",
  });
  const [previewOpen, setPreviewOpen] = useState(false);
  const manageListingsTab = route.listingsTab;
  const setManageListingsTab = (value) => setRouteField("listingsTab", value);
  const [expandedListingImagesId, setExpandedListingImagesId] = useState(null);
  // Which photo (if any) is mid-way through being hidden, so a reason can
  // be collected before actually confirming — { listingId, url } | null.
  const [hidingImageDraft, setHidingImageDraft] = useState(null);
  const [hideImageReason, setHideImageReason] = useState("");
  const salesTab = route.salesTab;
  const setSalesTab = (value) => setRouteField("salesTab", value);
  const [quickEditId, setQuickEditId] = useState(null);
  const [quickEditDraft, setQuickEditDraft] = useState({ price: "", quantity: "" });
  const [uploading, setUploading] = useState(false);
  const [photoUploadProgress, setPhotoUploadProgress] = useState([]); // [{name, status: 'uploading'|'done'|'error', message}]
  const [uploadingLicense, setUploadingLicense] = useState(false);
  const [idVerifyOpen, setIdVerifyOpen] = useState(false);
  const [idVerifyForm, setIdVerifyForm] = useState({ idType: "Passport", idCountry: "", licenseNumber: "" });
  const [bankStatementDraft, setBankStatementDraft] = useState(null);
  const [uploadingBankStatement, setUploadingBankStatement] = useState(false);
  const [verifiedSellerIdForm, setVerifiedSellerIdForm] = useState({ idType: "nin" });
  const [verifiedSellerIdImages, setVerifiedSellerIdImages] = useState({ front: "", back: "" });
  const [uploadingVerifiedSellerId, setUploadingVerifiedSellerId] = useState(false);
  const [verifiedSellerConsent, setVerifiedSellerConsent] = useState(false);
  const [premiumSellerLimit, setPremiumSellerLimit] = useState("25000000");
  const [premiumSellerConsent, setPremiumSellerConsent] = useState(false);
  const [casualVerificationOpen, setCasualVerificationOpen] = useState(false);
  const [casualSellerStatus, setCasualSellerStatus] = useState(null);
  const [uploadingPodKey, setUploadingPodKey] = useState(null);
  const [deliveryPhotoTarget, setDeliveryPhotoTarget] = useState(null);
  const [uploadingDeliverySelfieKey, setUploadingDeliverySelfieKey] = useState(null);
  const [deliverySelfieDrafts, setDeliverySelfieDrafts] = useState({});
  const [selfDeliveryActionKey, setSelfDeliveryActionKey] = useState(null);
  const [deliverySelfieCameraTarget, setDeliverySelfieCameraTarget] = useState(null);
  const [deliverySelfieCameraReady, setDeliverySelfieCameraReady] = useState(false);
  const deliverySelfieVideoRef = useRef(null);
  const deliverySelfieStreamRef = useRef(null);
  const [uploadingReturnEvidenceKey, setUploadingReturnEvidenceKey] = useState(null);
  const [packingSlipOrder, setPackingSlipOrder] = useState(null);
  const [deliveryTokens, setDeliveryTokens] = useState({});
  const [generatingTokenKey, setGeneratingTokenKey] = useState(null);
  const [redeemTokenDrafts, setRedeemTokenDrafts] = useState({});
  const [redeemingTokenKey, setRedeemingTokenKey] = useState(null);
  const [uploadingMessagePhoto, setUploadingMessagePhoto] = useState(false);
  const [reportMessageId, setReportMessageId] = useState(null);
  const [reportReasonDraft, setReportReasonDraft] = useState("");
  const [rejectModalUsername, setRejectModalUsername] = useState(null);
  const [rejectReasonDraft, setRejectReasonDraft] = useState("");
  const [vacationOpen, setVacationOpen] = useState(false);
  const [vacationForm, setVacationForm] = useState({ returnDate: "", message: "" });
  // Email verification (stage one of sign-up) — mirrors the phone
  // verification pattern above, but for email since SMS is paused for now.
  const [pendingEmailVerification, setPendingEmailVerification] = useState(null);
  const [emailCodeInput, setEmailCodeInput] = useState("");
  const [emailVerifyError, setEmailVerifyError] = useState("");
  // Stage two of sign-up — the fuller profile form, shown right after a
  // fresh account is created OR whenever a logged-in user's profile isn't
  // complete yet, so they can always resume where they left off.
  const [profileStageOpen, setProfileStageOpen] = useState(false);
  const [profileStageError, setProfileStageError] = useState("");

  useEffect(() => {
    if (!sessionChecked || isAdminHost() || currentUser || !PRIVATE_VIEWS.has(view)) return;
    setAuthReturnView(view);
    setRoute((previous) => ({ ...previous, view: "signin", next: marketplaceRouteUrl(previous) }));
  }, [sessionChecked, currentUser, view]);
  useEffect(() => {
    if (view !== "dashboard" || !sessionChecked || !currentUser) return;
    const target = route.sellerSection === "orders" ? "seller-sales" : route.sellerSection === "listings" ? "seller-listings" : "seller-overview";
    const timer = setTimeout(() => document.getElementById(target)?.scrollIntoView({ behavior: "auto" }), 0);
    return () => clearTimeout(timer);
  }, [view, route.sellerSection, sessionChecked, currentUser, orders.length]);

  const showToast = useCallback((msg) => {
    setToast(msg);
    setTimeout(() => setToast(""), 2500);
  }, []);

  useEffect(() => {
    const slideCount = homepageAds.filter((ad) => ad.imageUrl).length;
    if (homepageHeroSlide >= Math.max(slideCount, 1)) setHomepageHeroSlide(0);
    if (slideCount <= 1 || homepageHeroPaused || view !== "browse") return undefined;
    const interval = setInterval(() => {
      setHomepageHeroSlide((current) => (current + 1) % slideCount);
    }, 7000);
    return () => clearInterval(interval);
  }, [homepageAds, homepageHeroPaused, homepageHeroSlide, view]);

  useEffect(() => {
    // Slide 1 is the LCP resource. Preload the remaining slides only after the
    // initial page has had time to settle.
    const timer = setTimeout(() => {
      homepageAds.slice(1).forEach((ad) => {
        [ad.imageUrl, ad.posterUrl].filter(Boolean).forEach((src) => {
          const preload = new Image();
          preload.src = src;
        });
      });
    }, 2500);
    return () => clearTimeout(timer);
  }, [homepageAds]);

  useEffect(() => {
    (async () => {
      try {
        const res = await window.storage.get("stallyard-listings", true);
        const localListings = res ? JSON.parse(res.value) : [];
        setListings(localListings);
        try {
          const listingsRes = await backendFetch(`${BACKEND_URL}/listings`);
          if (listingsRes.ok) {
            const { listings: rows } = await listingsRes.json();
            const merged = rows.map((row) =>
              backendListingToFrontend(row, localListings.find((l) => l.id === row.id))
            );
            setListings(merged);
            await window.storage.set("stallyard-listings", JSON.stringify(merged), true);
          }
        } catch {
          // couldn't reach backend for listings — keep local copy
        }
      } catch {
        setListings([]);
      }
      let bootstrapAuthenticated = false;
      try {
        const sessionRes = await backendFetch(`${BACKEND_URL}/session/me`);
        if (sessionRes.ok) {
          const sessionData = await sessionRes.json();
          bootstrapAuthenticated = true;
          setAuthToken("cookie-session");
          if (sessionData.user?.username) {
            setSessionUserProfile(sessionData.user);
            setCurrentUser(sessionData.user.username);
            await window.storage.set("stallyard-session", sessionData.user.username, false);
          }
        } else {
          setAuthToken(null);
          setSessionUserProfile(null);
          await window.storage.delete("stallyard-session", false);
          // Remove any token left behind by pre-cookie versions of Stallyard.
          await window.storage.delete("stallyard-auth-token", false);
        }
      } catch {
        // If the backend cannot be reached, do not trust an old browser token.
        setAuthToken(null);
      }
      let resolvedMembers = [];
      try {
        const membersRes = await window.storage.get("stallyard-members", true);
        const localMembers = membersRes ? JSON.parse(membersRes.value) : [];
        resolvedMembers = localMembers;
        setMembers(localMembers);
        try {
          const usersRes = await backendFetch(`${BACKEND_URL}/users`);
          if (usersRes.ok) {
            const { users } = await usersRes.json();
            const merged = users.map((u) =>
              backendUserToMember(u, localMembers.find((m) => m.username === u.username))
            );
            resolvedMembers = merged;
            setMembers(merged);
            await window.storage.set("stallyard-members", JSON.stringify(merged), true);
          }
        } catch {
          // couldn't reach backend for member list — keep local copy
        }
      } catch {
        setMembers([]);
      }
      setMembersLoaded(true);
      // Authentication is server-authoritative. The HttpOnly cookie/session
      // check above decides whether the browser is signed in; a stale local
      // username can never restore access by itself.
      if (!bootstrapAuthenticated) setCurrentUser(null);
      setSessionChecked(true);
      try {
        const cartRes = await window.storage.get("stallyard-cart", false);
        setCart(cartRes ? JSON.parse(cartRes.value) : []);
      } catch {
        setCart([]);
      }
      try {
        const watchlistRes = await window.storage.get("stallyard-watchlist", false);
        setWatchlist(watchlistRes ? JSON.parse(watchlistRes.value) : []);
      } catch {
        setWatchlist([]);
      }
      try {
        const recentRes = await window.storage.get("stallyard-recently-viewed", false);
        setRecentlyViewedIds(recentRes ? JSON.parse(recentRes.value) : []);
      } catch {
        setRecentlyViewedIds([]);
      }
      try {
        const readRes = await window.storage.get("stallyard-message-reads", false);
        setMessageReadState(readRes ? JSON.parse(readRes.value) : {});
      } catch {
        setMessageReadState({});
      }
      setOrders([]);
      try {
        const settingsRes = await backendFetch(`${BACKEND_URL}/settings`);
        if (settingsRes.ok) {
          const raw = await settingsRes.json();
          setSettings({ commissionRate: raw.commissionRate, taxRate: raw.taxRate || 0, authImage: raw.authImage || "" });
        }
      } catch {
        // keep default settings
      }
      try {
        const adsRes = await backendFetch(`${BACKEND_URL}/homepage-ads`);
        if (adsRes.ok) {
          const raw = await adsRes.json();
          const returned = new Map((raw.ads || []).map((ad) => [Number(ad.slot), ad]));
          setHomepageAds([1, 2, 3].map((slot) => {
            const ad = returned.get(slot) || {};
            return {
              slot,
              imageUrl: ad.image_url || "",
              mediaType: "image",
              posterUrl: ad.poster_url || "",
              linkUrl: ad.link_url || "",
            };
          }));
        }
      } catch {
        // Keep the three empty promotional slots if the API is temporarily unavailable.
      }
      try {
        const contentRes = await backendFetch(`${BACKEND_URL}/content`);
        if (contentRes.ok) {
          const raw = await contentRes.json();
          setContent({
            banners: raw.banners.map((b) => ({
              id: b.id,
              message: b.message,
              tone: b.tone,
              isActive: b.is_active,
              mediaType: b.media_type,
              imageUrl: b.image_url || "",
              videoUrl: b.video_url || "",
            })),
            articles: raw.articles.map((a) => ({
              id: a.id,
              title: a.title,
              body: a.body,
              updatedAt: a.updated_at ? new Date(a.updated_at).getTime() : Date.now(),
            })),
            faqs: raw.faqs.map((f) => ({ id: f.id, question: f.question, answer: f.answer })),
          });
        }
      } catch {
        // keep default empty content
      }
      try {
        const policiesRes = await backendFetch(`${BACKEND_URL}/policies`);
        if (policiesRes.ok) {
          const { policies: rows } = await policiesRes.json();
          const next = {};
          rows.forEach((p) => {
            next[p.category] = p.body || "";
          });
          setPolicies(next);
        }
      } catch {
        // keep default empty policies
      }
      setWithdrawals([]);
      setThreads([]); // loaded fresh once we know who's logged in, see the effect below
      try {
        const reviewsRes = await backendFetch(`${BACKEND_URL}/reviews`);
        if (reviewsRes.ok) {
          const { reviews: rows } = await reviewsRes.json();
          setReviews(rows.map((r) => backendReviewToFrontend(r, resolvedMembers)));
        }
      } catch {
        // couldn't reach backend for reviews — leave empty
      }
      try {
        const followsRes = await backendFetch(`${BACKEND_URL}/follows`);
        if (followsRes.ok) {
          const { follows: rows } = await followsRes.json();
          setFollows(
            rows.map((r) => ({ followerUsername: r.follower_username, followedUsername: r.followed_username }))
          );
        }
      } catch {
        // couldn't reach backend for follows — leave empty, follow button will still work
      }
      setLoaded(true);
    })();
  }, []);

  // Records a listing as viewed the moment it's opened, regardless of which
  // of the several places in the app opened it (search results, a seller's
  // storefront, watchlist, etc) — one hook point instead of several.
  useEffect(() => {
    if (selected?.id) recordRecentlyViewed(selected.id);
    setGalleryZoomOpen(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);


  // Orders and withdrawals are private, per-user data — load them fresh from
  // the real backend whenever the signed-in user (or their token) changes,
  // rather than during the anonymous initial load above.
  useEffect(() => {
    (async () => {
      if (!currentUser || !authToken) {
        setOrders([]);
        setWithdrawals([]);
        setNotifications([]);
        setMyWarnings([]);
        setMyTickets([]);
        setAdminTickets([]);
        setSavedCards([]);
        setSavedAddresses([]);
        setAdminDisputes([]);
        setSellerReports([]);
        setAdminLocalDeliveries([]);
        setLocalDriverReports([]);
        setMyDisputes([]);
        setDeliveryAssignments({});
        setDeliveryAssignmentDrafts({});
        setDeliveryAssignmentSecrets({});
        return;
      }
      const isAdmin = members.find((m) => m.username === currentUser)?.isAdmin;
      try {
        const notifRes = await authFetch(`${BACKEND_URL}/notifications/mine`);
        if (notifRes.ok) {
          const { notifications: rows } = await notifRes.json();
          setNotifications(
            rows.map((n) => ({
              id: n.id,
              type: n.type,
              message: n.message,
              read: n.read,
              createdAt: n.created_at ? new Date(n.created_at).getTime() : Date.now(),
            }))
          );
        }
      } catch {
        // couldn't reach backend for notifications — leave empty
      }
      try {
        const myDisputesRes = await authFetch(`${BACKEND_URL}/disputes/mine`);
        if (myDisputesRes.ok) {
          const { disputes } = await myDisputesRes.json();
          setMyDisputes(disputes || []);
        }
      } catch {
        // dispute cases are supplementary to the order view
      }
      try {
        const [mineRes, sellingRes, adminRes, assignmentRes] = await Promise.all([
          authFetch(`${BACKEND_URL}/orders/mine`),
          authFetch(`${BACKEND_URL}/orders/selling`),
          isAdmin && hasAdminPermission(members.find((m) => m.username === currentUser), "order_access")
            ? authFetch(`${BACKEND_URL}/orders`)
            : Promise.resolve(null),
          !isAdmin ? authFetch(`${BACKEND_URL}/delivery-assignments/mine`) : Promise.resolve(null),
        ]);
        const byId = new Map();
        for (const res of [mineRes, sellingRes, adminRes]) {
          if (!res || !res.ok) continue;
          const { orders: rows } = await res.json();
          for (const row of rows) byId.set(row.id, backendOrderToFrontend(row));
        }
        setOrders([...byId.values()].sort((a, b) => b.createdAt - a.createdAt));
        if (assignmentRes?.ok) {
          const data = await assignmentRes.json();
          const byItem = {};
          for (const assignment of data.assignments || []) byItem[assignment.orderItemId] = assignment;
          setDeliveryAssignments(byItem);
        }
      } catch {
        // couldn't reach backend for orders — leave empty rather than show stale/fake data
      }
      try {
        const [mineWRes, adminWRes] = await Promise.all([
          authFetch(`${BACKEND_URL}/withdrawals/mine`),
          isAdmin ? authFetch(`${BACKEND_URL}/withdrawals`) : Promise.resolve(null),
        ]);
        const byId = new Map();
        for (const res of [mineWRes, adminWRes]) {
          if (!res || !res.ok) continue;
          const { withdrawals: rows } = await res.json();
          for (const row of rows) {
            byId.set(row.id, {
              id: row.id,
              sellerUsername: row.seller_username,
              sellerId: row.seller_id,
              amount: Number(row.amount),
              status: row.status,
              failureReason: row.failure_reason,
              requestedAt: row.requested_at ? new Date(row.requested_at).getTime() : Date.now(),
              processedAt: row.processed_at ? new Date(row.processed_at).getTime() : null,
            });
          }
        }
        setWithdrawals([...byId.values()].sort((a, b) => b.requestedAt - a.requestedAt));
      } catch {
        // couldn't reach backend for withdrawals — leave empty
      }
      if (isAdmin) {
        try {
          const disputesRes = await authFetch(`${BACKEND_URL}/disputes`);
          if (disputesRes.ok) {
            const { disputes } = await disputesRes.json();
            setAdminDisputes(disputes || []);
          }
        } catch {
          // couldn't reach backend for dispute cases — leave empty
        }
        try {
          const reportsRes = await authFetch(`${BACKEND_URL}/message-reports`);
          if (reportsRes.ok) {
            const { reports } = await reportsRes.json();
            setMessageReports(reports);
          }
        } catch {
          // couldn't reach backend for message reports — leave empty
        }
        try {
          const reviewReportsRes = await authFetch(`${BACKEND_URL}/review-reports`);
          if (reviewReportsRes.ok) {
            const { reports } = await reviewReportsRes.json();
            setReviewReports(reports);
          }
        } catch {
          // couldn't reach backend for review reports — leave empty
        }
        try {
          const accountReportsRes = await authFetch(`${BACKEND_URL}/account-reports`);
          if (accountReportsRes.ok) {
            const { reports } = await accountReportsRes.json();
            setAccountReports(reports);
          }
        } catch {
          // couldn't reach backend for account reports — leave empty
        }
        try {
          const sellerReportsRes = await authFetch(`${BACKEND_URL}/seller-reports`);
          if (sellerReportsRes.ok) {
            const { reports } = await sellerReportsRes.json();
            setSellerReports(reports || []);
          }
        } catch {
          // couldn't reach backend for seller reports — leave empty
        }
        try {
          const [deliveriesRes, driverReportsRes] = await Promise.all([
            authFetch(`${BACKEND_URL}/admin/local-deliveries`),
            authFetch(`${BACKEND_URL}/admin/local-driver-reports`),
          ]);
          if (deliveriesRes.ok) {
            const { deliveries } = await deliveriesRes.json();
            setAdminLocalDeliveries(deliveries || []);
          }
          if (driverReportsRes.ok) {
            const { reports } = await driverReportsRes.json();
            setLocalDriverReports(reports || []);
          }
        } catch {
          // Local-delivery administration is available only to permitted staff.
        }
      }
      if (!isAdmin) {
        try {
          const sellerReportsRes = await authFetch(`${BACKEND_URL}/seller-reports/mine`);
          if (sellerReportsRes.ok) {
            const { reports } = await sellerReportsRes.json();
            setSellerReports(reports || []);
          }
        } catch {
          // Seller report history is supplementary to the buyer dashboard.
        }
      }
      try {
        const warningsRes = await authFetch(`${BACKEND_URL}/warnings/mine`);
        if (warningsRes.ok) {
          const { warnings } = await warningsRes.json();
          setMyWarnings(warnings);
        }
      } catch {
        // couldn't reach backend for warnings — leave empty
      }
      try {
        const ticketsRes = await authFetch(`${BACKEND_URL}/support-tickets/mine`);
        if (ticketsRes.ok) {
          const { tickets } = await ticketsRes.json();
          setMyTickets(tickets);
        }
      } catch {
        // couldn't reach backend for tickets — leave empty
      }
      if (isAdmin) {
        try {
          const adminTicketsRes = await authFetch(`${BACKEND_URL}/support-tickets`);
          if (adminTicketsRes.ok) {
            const { tickets } = await adminTicketsRes.json();
            setAdminTickets(tickets);
          }
        } catch {
          // couldn't reach backend for admin tickets — leave empty
        }
      }
      try {
        const cartRes = await authFetch(`${BACKEND_URL}/cart`);
        if (cartRes.ok) {
          const { items } = await cartRes.json();
          const mapped = items.map((i) => ({
            id: i.listing_id,
            qty: i.qty,
            ...(i.offer_price != null ? { offerPrice: Number(i.offer_price) } : {}),
          }));
          setCart(mapped);
          await window.storage.set("stallyard-cart", JSON.stringify(mapped), false);
        }
      } catch {
        // couldn't reach backend for cart — keep whatever loaded locally
      }
      try {
        const watchlistRes = await authFetch(`${BACKEND_URL}/watchlist`);
        if (watchlistRes.ok) {
          const { listingIds } = await watchlistRes.json();
          setWatchlist(listingIds);
          await window.storage.set("stallyard-watchlist", JSON.stringify(listingIds), false);
        }
      } catch {
        // couldn't reach backend for watchlist — keep whatever loaded locally
      }
      const myBackendId = members.find((m) => m.username === currentUser)?.backendId;
      if (myBackendId) {
        try {
          const threadsRes = await authFetch(`${BACKEND_URL}/threads/${myBackendId}`);
          if (threadsRes.ok) {
            const { threads: threadRows } = await threadsRes.json();
            const withMessages = await Promise.all(
              threadRows.map(async (t) => {
                const msgRes = await authFetch(`${BACKEND_URL}/messages/${t.id}`);
                const messageRows = msgRes.ok ? (await msgRes.json()).messages : [];
                return backendThreadToFrontend(t, messageRows, members, listings);
              })
            );
            setThreads(withMessages.sort((a, b) => b.updatedAt - a.updatedAt));
          }
        } catch {
          // couldn't reach backend for threads — leave empty
        }
      } else {
        setThreads([]);
      }
      try {
        const cardsRes = await authFetch(`${BACKEND_URL}/saved-cards`);
        if (cardsRes.ok) setSavedCards(await cardsRes.json());
      } catch {
        // couldn't reach backend for saved cards — leave empty
      }
      try {
        const addressesRes = await authFetch(`${BACKEND_URL}/addresses`);
        if (addressesRes.ok) setSavedAddresses(await addressesRes.json());
      } catch {
        // couldn't reach backend for saved addresses — leave empty
      }
    })();
  }, [currentUser, authToken, members, listings]);

  useEffect(() => {
    if (view !== "messages") return;
    const interval = setInterval(async () => {
      try {
        const threadsRes = await window.storage.get("stallyard-messages", true);
        if (threadsRes) setThreads(JSON.parse(threadsRes.value));
      } catch {
        // ignore polling errors
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [view]);

  useEffect(() => {
    const interval = setInterval(() => setNowTick(Date.now()), 30000);
    return () => clearInterval(interval);
  }, []);

  // Refresh buyer orders while signed in so an active seller location moves on
  // the buyer's order page without requiring a manual browser refresh.
  useEffect(() => {
    if (!currentUser || !authToken) return undefined;
    const interval = setInterval(async () => {
      try {
        const res = await authFetch(`${BACKEND_URL}/orders/mine`);
        if (!res.ok) return;
        const { orders: rows } = await res.json();
        const refreshed = new Map((rows || []).map((row) => [row.id, backendOrderToFrontend(row)]));
        setOrders((all) => all.map((order) => refreshed.get(order.id) || order));
      } catch {
        // Keep the last known location during a temporary network interruption.
      }
    }, 15000);
    return () => clearInterval(interval);
  }, [currentUser, authToken]);

  useEffect(() => {
    if (!currentUser || !authToken || sessionUserProfile?.is_admin) { setCasualSellerStatus(null); return; }
    let cancelled = false;
    let refreshInFlight = false;
    const refreshSellerStage = async () => {
      if (refreshInFlight) return;
      refreshInFlight = true;
      try {
        const [statusResponse, sessionResponse] = await Promise.all([
          authFetch(`${BACKEND_URL}/casual-seller/status`),
          authFetch(`${BACKEND_URL}/session/me`),
        ]);
        if (sessionResponse.status === 401 || sessionResponse.status === 403) {
          if (cancelled) return;
          let sessionMessage = sessionResponse.status === 403
            ? "This account has been suspended. Contact Stallyard support."
            : "Your session expired. Please sign in again.";
          try {
            const sessionError = await sessionResponse.json();
            if (sessionError?.error) sessionMessage = sessionError.error;
          } catch {
            // Use the safe fallback message when the server sends no JSON body.
          }
          setCasualSellerStatus(null);
          setSessionUserProfile(null);
          setCurrentUser(null);
          setAuthToken(null);
          try {
            await window.storage.delete("stallyard-session", false);
            await window.storage.delete("stallyard-auth-token", false);
          } catch {
            // The server has already ended the session; local cleanup is best effort.
          }
          showToast(sessionMessage);
          return;
        }
        const statusData = statusResponse.ok ? await statusResponse.json() : null;
        const sessionData = sessionResponse.ok ? await sessionResponse.json() : null;
        if (cancelled) return;
        if (statusData) setCasualSellerStatus(statusData);
        if (sessionData?.user?.username === currentUser) setSessionUserProfile(sessionData.user);
      } catch {
        // Keep the last confirmed seller stage during a temporary network interruption.
      } finally {
        refreshInFlight = false;
      }
    };
    refreshSellerStage();
    const interval = setInterval(refreshSellerStage, 20000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [currentUser, authToken, sessionUserProfile?.is_admin]);

  useEffect(() => {
    if (!cartOpen) return;
    const saved = members.find((m) => m.username === currentUser)?.shippingAddress;
    const isBlank = !shippingForm.street && !shippingForm.city && !shippingForm.zip;
    if (saved && isBlank) {
      setShippingForm({ ...saved, country: "Nigeria" });
    } else if (!shippingForm.fullName && currentMember) {
      setShippingForm((f) => ({ ...f, fullName: currentMember.displayName }));
    }
  }, [cartOpen]);

  const persistListings = async (next) => {
    setListings(next);
    try {
      await window.storage.set("stallyard-listings", JSON.stringify(next), true);
    } catch {
      showToast("Couldn't save — try again");
    }
  };

  const persistMembers = async (next) => {
    setMembers(next);
    try {
      await window.storage.set("stallyard-members", JSON.stringify(next), true);
    } catch {
      showToast("Couldn't save — try again");
    }
  };

  const submitIdVerification = async () => {
    if (!idVerifyForm.idCountry.trim()) {
      showToast("Enter the country that issued your ID or passport");
      return;
    }
    await persistMembers(
      members.map((m) =>
        m.username === currentUser
          ? {
              ...m,
              idType: idVerifyForm.idType,
              idCountry: idVerifyForm.idCountry.trim(),
              licenseNumber: idVerifyForm.licenseNumber.trim(),
            }
          : m
      )
    );
    setIdVerifyOpen(false);
    setIdVerifyForm({ idType: "Passport", idCountry: "", licenseNumber: "" });
    showToast("ID verification added — you can keep selling");
  };

  const applyToSell = async () => {
    const target = members.find((m) => m.username === currentUser);
    if (!target?.backendId) {
      showToast("Your account is still loading — wait a moment and try again");
      return;
    }
    try {
        if (!verifiedSellerIdImages.front) { showToast("Upload the front of your identification"); return; }
        if (!bankStatementDraft) { showToast("Upload a bank statement before applying for verified seller status"); return; }
        if (!verifiedSellerConsent) { showToast("Accept the verified-seller declaration before applying"); return; }
        const res = await authFetch(`${BACKEND_URL}/verified-seller/apply`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ bankStatement: bankStatementDraft, consent: true, ...verifiedSellerIdForm,
            idFront: verifiedSellerIdImages.front, idBack: verifiedSellerIdImages.back || null }),
        });
        if (!res.ok) {
          let message = "Couldn't submit application — try again";
          try { const data = await res.json(); if (data?.error) message = data.error; } catch {}
          showToast(message);
          return;
        }
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    setSessionUserProfile((current) => current ? {
      ...current,
      has_applied_to_sell: true,
      verification_status: "pending",
      rejection_reason: null,
    } : current);
    await persistMembers(
      members.map((m) =>
        m.username === currentUser
          ? {
              ...m,
              hasAppliedToSell: true,
              verificationStatus: "pending",
              rejectionReason: "",
              bankStatementUrl: null,
            }
          : m
      )
    );
    setBankStatementDraft(null);
    setVerifiedSellerIdForm({ idType: "nin" });
    setVerifiedSellerIdImages({ front: "", back: "" });
    setVerifiedSellerConsent(false);
    showToast("Verified Seller application submitted — you'll be notified after admin review");
  };

  const applyForPremiumSeller = async () => {
    if (casualSellerStatus?.premiumApplication?.status === "pending") {
      showToast("Your Premium Seller application is already awaiting review");
      return;
    }
    const requestedLimit = Number(premiumSellerLimit);
    if (!Number.isFinite(requestedLimit) || requestedLimit <= 20000000) {
      showToast("Request a limit above ₦20,000,000");
      return;
    }
    if (!bankStatementDraft) { showToast("Upload a recent supporting bank statement"); return; }
    if (!premiumSellerConsent) { showToast("Accept the Premium Seller declaration"); return; }
    try {
      const response = await authFetch(`${BACKEND_URL}/premium-seller/apply`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requestedLimit, supportingDocument: bankStatementDraft, consent: true }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Premium Seller application could not be submitted");
      setBankStatementDraft(null);
      setPremiumSellerConsent(false);
      setCasualSellerStatus((current) => current ? { ...current, premiumApplication: {
        reference: data.reference,
        requested_limit: requestedLimit,
        status: "pending",
        decision_reason: null,
        created_at: new Date().toISOString(),
      } } : current);
      showToast(`Premium Seller application ${data.reference} submitted for review`);
    } catch (err) { showToast(err.message || "Couldn't reach the server — try again"); }
  };

  const saveVacationSettings = async () => {
    await persistMembers(
      members.map((m) =>
        m.username === currentUser
          ? {
              ...m,
              vacationMode: true,
              vacationReturnDate: vacationForm.returnDate,
              vacationMessage: vacationForm.message.trim(),
            }
          : m
      )
    );
    setVacationOpen(false);
    showToast("Vacation mode turned on — buyers will see a notice on your listings");
  };

  const endVacation = async () => {
    await persistMembers(
      members.map((m) => (m.username === currentUser ? { ...m, vacationMode: false } : m))
    );
    showToast("Vacation mode turned off — welcome back!");
  };

  const setSession = async (username) => {
    setCurrentUser(username);
    try {
      if (username) await window.storage.set("stallyard-session", username, false);
      else await window.storage.delete("stallyard-session", false);
    } catch {
      // session save failed silently; user stays logged in for this visit
    }
  };

  const saveAuthToken = async (authenticated) => {
    // This is only an in-memory signed-in marker used by existing UI guards.
    // The real JWT lives exclusively in the backend's HttpOnly cookie.
    setAuthToken(authenticated ? "cookie-session" : null);
    try {
      // Delete legacy JWT storage from versions released before Fix #14.
      await window.storage.delete("stallyard-auth-token", false);
    } catch {
      // best-effort cleanup only
    }
  };

  // Protected requests rely on the Secure HttpOnly cookie. No bearer token is
  // readable by or attached from frontend JavaScript.
  const authFetch = (url, options = {}) => backendFetch(url, options);

  const register = async () => {
    setAuthError("");
    const username = authForm.username.trim().toLowerCase();
    if (!username || !authForm.password) {
      setAuthError("Enter a username and password");
      return;
    }
    if (authForm.password.length < 8) {
      setAuthError("Password should be at least 8 characters");
      return;
    }
    if (!authForm.email.trim() || !isValidEmail(authForm.email)) {
      setAuthError("Enter a valid email address");
      return;
    }
    const signupDraft = {
      username,
      email: authForm.email.trim(),
      password: authForm.password,
    };
    let sendRes;
    try {
      sendRes = await backendFetch(`${BACKEND_URL}/email-verify/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: signupDraft.email }),
      });
    } catch {
      setAuthError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const sendData = await sendRes.json();
    if (!sendRes.ok) {
      setAuthError(sendData.error || "Couldn't send a verification code to that email.");
      return;
    }
    setPendingEmailVerification({ signupDraft });
    setEmailVerifyError("");
    setEmailCodeInput("");
  };

  const resendEmailCode = async () => {
    if (!pendingEmailVerification) return;
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/email-verify/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingEmailVerification.signupDraft.email }),
      });
    } catch {
      setEmailVerifyError("Couldn't reach the server — try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setEmailVerifyError(data.error || "Couldn't resend the code — try again.");
      return;
    }
    setEmailVerifyError("");
    showToast("New code sent");
  };

  const confirmEmailCode = async () => {
    if (!pendingEmailVerification) return;
    const draft = pendingEmailVerification.signupDraft;
    let checkRes;
    try {
      checkRes = await backendFetch(`${BACKEND_URL}/email-verify/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: draft.email, code: emailCodeInput.trim() }),
      });
    } catch {
      setEmailVerifyError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const checkData = await checkRes.json();
    if (!checkRes.ok) {
      setEmailVerifyError(checkData.error || "Couldn't check that code — try again.");
      return;
    }
    if (!checkData.valid) {
      setEmailVerifyError("That code doesn't match — check and try again.");
      return;
    }
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: draft.username,
          email: draft.email,
          password: draft.password,
          emailVerified: true,
          onboardingIntent: registrationIntent === "seller" ? "sell" : "buy",
        }),
      });
    } catch {
      setEmailVerifyError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setEmailVerifyError(data.error || "Something went wrong creating your account.");
      return;
    }
    setSessionUserProfile(data.user);
    const newMember = backendUserToMember(data.user);
    await persistMembers([...members, newMember]);
    await saveAuthToken(true);
    await setSession(newMember.username);
    setIsNewAccountOnboarding(true);
    setPendingEmailVerification(null);
    setEmailCodeInput("");
    setEmailVerifyError("");
    setAuthForm({
      username: "",
      password: "",
      email: "",
      phone: "",
      displayName: "",
      firstName: "",
      lastName: "",
      otherName: "",
      dateOfBirth: "",
      gender: "",
      nationality: "",
      stateOfResidence: "",
      officeLocation: "",
      country: "Nigeria",
      licenseNumber: "",
      idType: "Passport",
      idCountry: "",
      accountType: "personal",
      licensePhotos: [],
    });
    showToast(
      newMember.isAdmin
        ? `Welcome, ${newMember.displayName} — you're the marketplace admin`
        : `You're in! Let's finish setting up your account.`
    );
    // Straight into stage two — but this can always be closed and resumed
    // later, since profile_complete stays false until it's actually done.
    setProfileStageOpen(true);
  };

  // Stage two: fill in name, phone, country, account type, and (if selling
  // in Nigeria) ID documents. Can be submitted partially — nothing here
  // is required to keep using the account — and re-opened any time from
  // wherever we surface the "finish your profile" prompt.
  const completeProfile = async () => {
    setProfileStageError("");
    if (!authForm.firstName.trim() || !authForm.lastName.trim()) {
      setProfileStageError("Enter your surname and first name");
      return;
    }
    if (!authForm.dateOfBirth) {
      setProfileStageError("Enter your date of birth");
      return;
    }
    const birthDate = new Date(`${authForm.dateOfBirth}T00:00:00Z`);
    const today = new Date();
    let profileAge = today.getUTCFullYear() - birthDate.getUTCFullYear();
    if (today.getUTCMonth() < birthDate.getUTCMonth() || (today.getUTCMonth() === birthDate.getUTCMonth() && today.getUTCDate() < birthDate.getUTCDate())) profileAge -= 1;
    if (Number.isNaN(birthDate.getTime()) || birthDate > today || profileAge < 18) {
      setProfileStageError("You must be at least 18 years old");
      return;
    }
    if (!authForm.gender) {
      setProfileStageError("Select your gender");
      return;
    }
    if (!authForm.nationality.trim()) {
      setProfileStageError("Enter your nationality");
      return;
    }
    if (!authForm.stateOfResidence) {
      setProfileStageError("Select your state of residence");
      return;
    }
    if (!authForm.country.trim()) {
      setProfileStageError("Enter your country of residence");
      return;
    }
    if (!isNigeria(authForm.country)) {
      setProfileStageError("Stallyard is available in Nigeria only. Enter Nigeria as your country of residence.");
      return;
    }
    if (authForm.phone.trim() && !isValidPhone(authForm.phone)) {
      setProfileStageError("That phone number doesn't look right — check it and try again");
      return;
    }
    if (!authForm.phone.trim()) {
      setProfileStageError("Enter your Nigerian phone number");
      return;
    }
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/profile/complete`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firstName: authForm.firstName.trim(),
          lastName: authForm.lastName.trim(),
          otherName: authForm.otherName.trim(),
          dateOfBirth: authForm.dateOfBirth,
          gender: authForm.gender,
          nationality: authForm.nationality.trim(),
          stateOfResidence: authForm.stateOfResidence,
          phone: authForm.phone.trim(),
          country: "Nigeria",
        }),
      });
    } catch {
      setProfileStageError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setProfileStageError(data.error || "Something went wrong saving your profile.");
      return;
    }
    const existing = members.find((m) => m.username === currentUser);
    setSessionUserProfile(data.user);
    const updatedMember = backendUserToMember(data.user, existing);
    await persistMembers(members.map((m) => (m.username === currentUser ? updatedMember : m)));
    setProfileStageOpen(false);
    if (isNewAccountOnboarding) {
      setAccountCreatedSuccess(true);
      setIsNewAccountOnboarding(false);
    } else {
      setView(updatedMember.onboardingIntent === "sell" ? "sell" : "buyerHome");
      showToast("Profile completed successfully");
    }
  };

  const openRegistration = (intent = "buyer") => {
    const normalizedIntent = ["buyer", "seller"].includes(intent) ? intent : "buyer";
    setRegistrationIntent(normalizedIntent);
    setAuthMode("register");
    setAuthError("");
    setPendingEmailVerification(null);
    setEmailVerifyError("");
    setAuthReturnView(normalizedIntent === "buyer" ? "browse" : "sell");
    setAuthForm((prev) => ({
      ...prev,
      accountType: "personal",
      country: "Nigeria",
    }));
    setView("signup");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const login = async () => {
    setAuthError("");
    const loginIdentifier = authForm.username.trim().toLowerCase();
    if (!loginIdentifier || !authForm.password) {
      setAuthError("Enter your username or email and password");
      return;
    }
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginIdentifier, password: authForm.password }),
      });
    } catch {
      setAuthError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setAuthError(data.error || "Something went wrong logging in.");
      return;
    }
    if (data.twoFactorRequired) {
      setPendingTwoFactor({ userId: data.userId, username: loginIdentifier, method: data.method || "email" });
      setTwoFactorCodeInput("");
      return;
    }
    await completeLogin(data, loginIdentifier);
  };

  // Handles both steps of admin login (authenticator app, then the
  // auto-sent email code) as well as the single-step email flow for
  // non-admin accounts, based on pendingTwoFactor.method.
  const verifyTwoFactorCode = async () => {
    if (!pendingTwoFactor) return;
    setAuthError("");
    const endpoint = pendingTwoFactor.method === "totp-email" ? "/login/verify-2fa-email" : "/login/verify-2fa";
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: pendingTwoFactor.userId, code: twoFactorCodeInput.trim() }),
      });
    } catch {
      setAuthError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setAuthError(data.error || "That code didn't work.");
      return;
    }
    if (data.emailStepRequired) {
      // Authenticator step passed — now the mandatory email step.
      setPendingTwoFactor((p) => ({ ...p, method: "totp-email" }));
      setTwoFactorCodeInput("");
      showToast("Authenticator code confirmed — check your email for the next code");
      return;
    }
    const username = pendingTwoFactor.username;
    setPendingTwoFactor(null);
    setTwoFactorCodeInput("");
    await completeLogin(data, username);
  };

  const completeLogin = async (data, username) => {
    // Email can be used to authenticate, but all marketplace ownership and
    // session state must continue to use the account's canonical username.
    const canonicalUsername = data.user?.username || username;
    const existing = members.find((m) => m.username === canonicalUsername);
    setSessionUserProfile(data.user);
    const member = backendUserToMember(data.user, existing);
    const nextMembers = existing
      ? members.map((m) => (m.username === canonicalUsername ? member : m))
      : [...members, member];
    await persistMembers(nextMembers);
    await saveAuthToken(true);
    await setSession(canonicalUsername);
    setAuthForm({
      username: "",
      password: "",
      email: "",
      phone: member.phone || "",
      displayName: "",
      firstName: member.firstName || "",
      lastName: member.lastName || "",
      otherName: member.otherName || "",
      dateOfBirth: member.dateOfBirth || "",
      gender: member.gender || "",
      nationality: member.nationality || "",
      stateOfResidence: member.stateOfResidence || "",
      officeLocation: member.officeLocation || "",
      country: member.country || "",
      licenseNumber: member.licenseNumber || "",
      idType: member.idType || "Passport",
      idCountry: member.idCountry || "",
      accountType: member.accountType || "personal",
      licensePhotos: member.licensePhotos || [],
    });
    if (!member.profileComplete) {
      // Picks up exactly where they left off — stage two opens pre-filled
      // with whatever they already saved, instead of starting fresh.
      setProfileStageOpen(true);
      showToast(`Welcome back, ${member.displayName} — let's finish your profile`);
    } else {
      if (route.next) {
        const destination = new URL(route.next, window.location.origin);
        setRoute(readMarketplaceRoute(destination));
      } else setView(authReturnView);
      showToast(`Welcome back, ${member.displayName}`);
    }
  };

  const requestPasswordReset = async () => {
    setResetError("");
    const username = resetIdentifier.trim().toLowerCase();
    if (!username) {
      setResetError("Enter your username");
      return;
    }
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/password-reset/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
    } catch {
      setResetError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setResetError(data.error || "Couldn't send a reset code.");
      return;
    }
    setPendingPasswordReset({ username, maskedEmail: data.maskedEmail, verified: false, resetToken: null });
    setResetCodeInput("");
  };

  const resendResetCode = async () => {
    if (!pendingPasswordReset) return;
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/password-reset/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: pendingPasswordReset.username }),
      });
    } catch {
      setResetError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setResetError(data.error || "Couldn't resend the code.");
      return;
    }
    setResetError("");
    showToast("New code sent");
  };

  const confirmResetCode = async () => {
    if (!pendingPasswordReset) return;
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/password-reset/verify-code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: pendingPasswordReset.username, code: resetCodeInput.trim() }),
      });
    } catch {
      setResetError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setResetError(data.error || "That code doesn't match — check and try again.");
      return;
    }
    setPendingPasswordReset({ ...pendingPasswordReset, verified: true, resetToken: data.resetToken });
    setResetError("");
  };

  const submitNewPassword = async () => {
    if (newPasswordForm.password.length < 8) {
      setResetError("Password should be at least 8 characters");
      return;
    }
    if (newPasswordForm.password !== newPasswordForm.confirm) {
      setResetError("Passwords don't match");
      return;
    }
    let res;
    try {
      res = await backendFetch(`${BACKEND_URL}/password-reset/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          resetToken: pendingPasswordReset.resetToken,
          newPassword: newPasswordForm.password,
        }),
      });
    } catch {
      setResetError("Couldn't reach the server — check your connection and try again.");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setResetError(data.error || "Couldn't update your password — try starting over.");
      return;
    }
    showToast("Password updated — you can log in now");
    setPendingPasswordReset(null);
    setResetIdentifier("");
    setResetCodeInput("");
    setNewPasswordForm({ password: "", confirm: "" });
    setResetError("");
    setAuthMode("login");
  };

  const logout = async () => {
    try {
      await backendFetch(`${BACKEND_URL}/logout`, { method: "POST" });
    } catch {
      // Clear local UI state even if the network is temporarily unavailable.
    }
    setAdminUnlockedUntil(null);
    if (typeof window !== "undefined") {
      window.sessionStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
    }
    await setSession(null);
    await saveAuthToken(null);
    setActiveThreadId(null);
    setActiveThreadOrderId(null);
    setSelected(null);
    setView("browse");
    if (isAdminHost()) {
      setAdminLoginMode(true);
      setAdminLoginStep("credentials");
      setAdminLoginCode("");
      window.history.replaceState({}, "", "/");
    } else {
      setAdminLoginMode(false);
    }
    showToast("Logged out");
  };

  const publicCurrentMember = members.find((m) => m.username === currentUser) || null;
  // For the signed-in user's own account, trust the authenticated /session/me
  // profile instead of the privacy-limited public /users record. This keeps
  // seller approval/verification state available without exposing it publicly.
  const currentMember = currentUser && sessionUserProfile?.username === currentUser
    ? backendUserToMember(sessionUserProfile, publicCurrentMember || undefined)
    : publicCurrentMember;
  const hasSellerListingAccess = !currentMember?.isAdmin && !currentMember?.sellerSuspended && !!(
    currentMember?.isApproved ||
    currentMember?.casualSellerStatus === "approved" || casualSellerStatus?.status === "approved"
  );
  const casualSellerContactReady = casualSellerStatus?.emailVerified === true && casualSellerStatus?.phoneVerified === true;

  useEffect(() => {
    const accountNumber = bankForm.accountNumber.replace(/\D/g, "");
    setBankOwnerConfirmed(false);
    if (!bankForm.bankCode || accountNumber.length !== 10 || !currentUser) {
      setBankResolution({ status: "idle", accountName: "", nameMatches: false, error: "" });
      return undefined;
    }
    let cancelled = false;
    const timer = setTimeout(async () => {
      setBankResolution({ status: "checking", accountName: "", nameMatches: false, error: "" });
      try {
        const response = await authFetch(`${BACKEND_URL}/paystack/resolve-account`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ bankCode: bankForm.bankCode, accountNumber }),
        });
        const data = await response.json();
        if (cancelled) return;
        if (!response.ok) setBankResolution({ status: "error", accountName: "", nameMatches: false, error: data.error || "Account could not be verified" });
        else setBankResolution({ status: "verified", accountName: data.accountName, nameMatches: !!data.nameMatches,
          error: data.nameMatches ? "" : "This name does not match your verified Stallyard identity." });
      } catch {
        if (!cancelled) setBankResolution({ status: "error", accountName: "", nameMatches: false, error: "Couldn't reach Paystack — try again" });
      }
    }, 600);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [bankForm.bankCode, bankForm.accountNumber, currentUser]);

  // Keep the admin origin completely separate from the buyer/seller storefront.
  // The admin host gets its own browser title and can render only the admin view.
  useEffect(() => {
    if (typeof window === "undefined") return;
    document.title = isAdminHost() ? "Stallyard Admin" : "Stallyard";
    if (isAdminHost()) {
      if (currentUser && currentMember?.isAdmin && view !== "admin") setView("admin");
    } else if (currentMember?.isAdmin) {
      // Staff identities belong on the dedicated operations console, not the marketplace.
      window.location.replace(ADMIN_URL);
    }
  }, [currentUser, currentMember?.isAdmin, view]);

  useEffect(() => {
    if (!currentMember?.isAdmin) return;
    const isSuperAdmin = !currentMember.adminRole || currentMember.adminRole === "super_admin";
    const canViewMembers = isSuperAdmin || hasAdminPermission(currentMember, "seller_verification");
    const canViewOrders = isSuperAdmin || hasAdminPermission(currentMember, "order_access");
    if (
      (adminTab === "overview" && !isSuperAdmin) ||
      (adminTab === "members" && !canViewMembers) ||
      (adminTab === "orders" && !canViewOrders)
    ) {
      const fallbackByRole = {
        seller_verification: "members",
        listing_moderator: "listings",
        order_dispute: "orders",
        finance: "orders",
        customer_support: "supportTickets",
      };
      setAdminTab(fallbackByRole[currentMember.adminRole] || "orders");
    }
  }, [currentMember?.isAdmin, currentMember?.adminRole, adminTab]);

  // The public /listings endpoint intentionally hides drafts/rejected/removed
  // records. Once a normal marketplace session is restored, refetch with the
  // token so the signed-in seller still receives their own non-public listings.
  useEffect(() => {
    if (!authToken || !currentMember || currentMember.isAdmin || isAdminHost()) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await authFetch(`${BACKEND_URL}/listings`);
        if (!res.ok) return;
        const { listings: rows } = await res.json();
        if (cancelled || !Array.isArray(rows)) return;
        const merged = rows.map((row) =>
          backendListingToFrontend(row, listings.find((l) => l.id === row.id))
        );
        setListings(merged);
        await window.storage.set("stallyard-listings", JSON.stringify(merged), true);
      } catch {
        // Keep the public/local listing copy if the authenticated refresh fails.
      }
    })();
    return () => { cancelled = true; };
    // Only rerun when the signed-in identity/token changes, not whenever listings changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authToken, currentMember?.backendId, currentMember?.isAdmin]);

  // Listing moderators need every status plus moderation metadata, so the admin
  // dashboard uses a dedicated protected endpoint rather than the public feed.
  useEffect(() => {
    if (!authToken || !currentMember?.isAdmin || adminTab !== "listings") return;
    if (!hasAdminPermission(currentMember, "listing_moderation")) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await authFetch(`${BACKEND_URL}/admin/listings`);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (!cancelled) showToast(data.error || "Couldn't load moderation listings");
          return;
        }
        if (cancelled || !Array.isArray(data.listings)) return;
        setListings(data.listings.map((row) => backendListingToFrontend(row)));
      } catch {
        if (!cancelled) showToast("Couldn't load moderation listings");
      }
    })();
    return () => { cancelled = true; };
  }, [authToken, currentMember?.isAdmin, currentMember?.adminRole, adminTab, showToast]);

  useEffect(() => {
    if (typeof window === "undefined" || !isAdminHost()) return;
    if (adminUnlockedUntil && adminUnlockedUntil > Date.now()) {
      window.sessionStorage.setItem(ADMIN_SESSION_STORAGE_KEY, String(adminUnlockedUntil));
    } else {
      window.sessionStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
    }
  }, [adminUnlockedUntil]);

  useEffect(() => {
    if (view !== "admin") return;
    const interval = setInterval(() => {
      // A not-yet-unlocked admin session is expected while the mandatory
      // password -> authenticator -> email re-auth flow is in progress.
      // Never restart that flow from the timeout watcher, otherwise Step 2
      // or Step 3 gets reset back to the password screen every 15 seconds.
      if (adminReauthStep) return;
      if (!adminUnlockedUntil || Date.now() > adminUnlockedUntil) {
        setAdminUnlockedUntil(null);
        showToast("Your admin session locked — re-enter your password to continue");
        openAdminPanel();
      }
    }, 15000);
    return () => clearInterval(interval);
  }, [view, adminUnlockedUntil, adminReauthStep]);

  // Admin is isolated on admin.stallyard.com. The old hidden-path approach
  // has been retired: the public marketplace never renders the admin panel.
  useEffect(() => {
    if (!sessionChecked) return;

    if (!isAdminHost()) {
      // Retire the legacy hidden admin URL by sending it to the dedicated
      // admin subdomain instead of rendering admin UI on the marketplace.
      if (window.location.pathname === "/0936746admin") {
        window.location.replace(ADMIN_URL);
      }
      if (view === "admin") setView("browse");
      setAdminLoginMode(false);
      return;
    }

    // On the dedicated admin host, never show the buyer/seller marketplace.
    if (!currentUser) {
      setAdminUnlockedUntil(null);
      window.sessionStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
      setView("browse");
      setAdminLoginMode(true);
      return;
    }

    if (!currentMember?.isAdmin) {
      setAdminUnlockedUntil(null);
      window.sessionStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
      // A non-admin session is not allowed on the admin origin.
      setView("browse");
      setAdminLoginMode(true);
      setAdminLoginError("Admin credentials required");
      return;
    }

    setAdminLoginMode(false);
    openAdminPanel();
  }, [sessionChecked, currentUser, currentMember?.isAdmin]);

  // Paystack redirects the buyer back to /order-confirmation?reference=...
  // once they've paid (or canceled). Confirms the payment actually
  // succeeded and finalizes the order — see verifyCheckout above.
  const orderConfirmationHandled = useRef(false);
  useEffect(() => {
    if (window.location.pathname !== "/order-confirmation") return;
    if (!sessionChecked || !currentUser) return; // need the auth token to call verify
    if (orderConfirmationHandled.current) return;
    const reference = new URLSearchParams(window.location.search).get("reference");
    window.history.replaceState({}, "", "/");
    if (!reference) return;
    orderConfirmationHandled.current = true;
    verifyCheckout(reference);
  }, [sessionChecked, currentUser]);

  const persistCart = async (next) => {
    setCart(next);
    try {
      await window.storage.set("stallyard-cart", JSON.stringify(next), false);
    } catch {
      showToast("Couldn't update your cart — try again");
    }
    if (authToken) {
      try {
        await authFetch(`${BACKEND_URL}/cart`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            items: next.map((c) => ({ listingId: c.id, qty: c.qty, offerPrice: c.offerPrice })),
          }),
        });
      } catch {
        // couldn't reach backend — local copy still saved, will resync next load
      }
    }
  };

  const persistWatchlist = async (next) => {
    setWatchlist(next);
    try {
      await window.storage.set("stallyard-watchlist", JSON.stringify(next), false);
    } catch {
      showToast("Couldn't update your watchlist — try again");
    }
    if (authToken) {
      try {
        await authFetch(`${BACKEND_URL}/watchlist`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ listingIds: next }),
        });
      } catch {
        // couldn't reach backend — local copy still saved, will resync next load
      }
    }
  };

  const markNotificationRead = async (id) => {
    setNotifications((ns) => ns.map((n) => (n.id === id ? { ...n, read: true } : n)));
    try {
      await authFetch(`${BACKEND_URL}/notifications/${id}/read`, { method: "PATCH" });
    } catch {
      // non-critical, fail silently — local state already updated
    }
  };

  const markNotificationsRead = async () => {
    setNotifications((ns) => ns.map((n) => ({ ...n, read: true })));
    try {
      await authFetch(`${BACKEND_URL}/notifications/mark-all-read`, { method: "PATCH" });
    } catch {
      // non-critical, fail silently — local state already updated
    }
  };

  // Local-only for now (no backend table for this yet, unlike cart/watchlist
  // which also sync to the server) — tracked per browser, capped at 12,
  // newest first, with no duplicates.
  const recordRecentlyViewed = async (listingId) => {
    const next = [listingId, ...recentlyViewedIds.filter((id) => id !== listingId)].slice(0, 12);
    setRecentlyViewedIds(next);
    try {
      await window.storage.set("stallyard-recently-viewed", JSON.stringify(next), false);
    } catch {
      // non-critical, fail silently
    }
  };

  const toggleWatchlist = (listingId) => {
    if (!currentUser) {
      setAuthMode("login");
      setAuthError("");
      setAuthReturnView(view);
      setView("signin");
      showToast("Log in to save items");
      return;
    }
    const isSaved = watchlist.includes(listingId);
    const next = isSaved ? watchlist.filter((id) => id !== listingId) : [...watchlist, listingId];
    persistWatchlist(next);
    showToast(isSaved ? "Removed from watchlist" : "Saved to watchlist");
  };

  const addToCart = (listing) => {
    if (cart.length > 0) {
      const firstItem = listings.find((l) => l.id === cart[0].id);
      const cartCurrency = firstItem?.currency || "NGN";
      const itemCurrency = listing.currency || "NGN";
      if (cartCurrency !== itemCurrency) {
        showToast(
          `Your cart has ${CURRENCIES.NGN.symbol} items — check out or clear your cart before adding ${CURRENCIES.NGN.symbol} items`
        );
        return;
      }
    }
    const existing = cart.find((c) => c.id === listing.id);
    const next = existing
      ? cart.map((c) => (c.id === listing.id ? { ...c, qty: c.qty + 1 } : c))
      : [...cart, { id: listing.id, qty: 1 }];
    persistCart(next);
    const vacation = getSellerVacationInfo(listing.ownerUsername);
    if (vacation) {
      const backText = vacation.returnDate
        ? ` The seller is away until ${new Date(vacation.returnDate).toLocaleDateString(undefined, { month: "short", day: "numeric" })}.`
        : " The seller is currently away.";
      showToast(`Added "${listing.title}" to cart —${backText} Shipping may be delayed.`);
    } else {
      showToast(`Added "${listing.title}" to cart`);
    }
  };

  const addToCartAtPrice = (listing, price) => {
    if (cart.length > 0 && !cart.find((c) => c.id === listing.id)) {
      const firstItem = listings.find((l) => l.id === cart[0].id);
      const cartCurrency = firstItem?.currency || "NGN";
      const itemCurrency = listing.currency || "NGN";
      if (cartCurrency !== itemCurrency) {
        showToast(
          `Your cart has ${CURRENCIES.NGN.symbol} items — check out or clear your cart before adding ${CURRENCIES.NGN.symbol} items`
        );
        return;
      }
    }
    const existing = cart.find((c) => c.id === listing.id);
    const next = existing
      ? cart.map((c) => (c.id === listing.id ? { ...c, offerPrice: price } : c))
      : [...cart, { id: listing.id, qty: 1, offerPrice: price }];
    persistCart(next);
    showToast(`Added "${listing.title}" to cart at your offer price`);
  };

  const patchListingOnBackend = async (id, body) => {
    if (typeof id !== "number") return true; // legacy local-only listing, nothing to sync
    try {
      const res = await authFetch(`${BACKEND_URL}/listings/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        showToast("Couldn't save that change — try again");
        return false;
      }
      return true;
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    }
  };

  const placeBid = async (listing, amount) => {
    if (!currentUser) {
      setAuthMode("login");
      setAuthError("");
      setAuthReturnView(view);
      setView("signin");
      showToast("Log in to place a bid");
      return;
    }
    if (listing.ownerUsername === currentUser) {
      showToast("You can't bid on your own listing");
      return;
    }
    const amt = Math.round(Number(amount) * 100) / 100;
    const minNext = Math.round((Number(listing.price) + 1) * 100) / 100;
    if (!amt || amt < minNext) {
      showToast(`Bid must be at least ${formatMoney(minNext, "NGN")}`);
      return;
    }
    if (listing.auctionEndTime && listing.auctionEndTime <= Date.now()) {
      showToast("This auction has already ended");
      return;
    }
    const bid = { bidderUsername: currentUser, bidderName: currentMember.displayName, amount: amt, at: Date.now() };
    const nextBidHistory = [...(listing.bidHistory || []), bid];
    const ok = await patchListingOnBackend(listing.id, {
      price: amt,
      highestBidderUsername: currentUser,
      bidHistory: nextBidHistory,
    });
    if (!ok) return;
    await persistListings(
      listings.map((l) =>
        l.id === listing.id
          ? { ...l, price: amt, highestBidderUsername: currentUser, bidHistory: nextBidHistory }
          : l
      )
    );
    setBidAmount("");
    showToast(`Bid placed — ${formatMoney(amt, "NGN")}`);
  };

  const updateCartQty = (id, qty) => {
    if (qty <= 0) {
      persistCart(cart.filter((c) => c.id !== id));
      return;
    }
    persistCart(cart.map((c) => (c.id === id ? { ...c, qty } : c)));
  };

  const removeFromCart = (id) => persistCart(cart.filter((c) => c.id !== id));

  const cartItems = cart
    .map((c) => {
      const listing = listings.find((l) => l.id === c.id);
      return listing
        ? { ...listing, qty: c.qty, price: c.offerPrice ?? listing.price, isOfferPrice: c.offerPrice != null }
        : null;
    })
    .filter(Boolean);

  const cartCount = cartItems.reduce((s, i) => s + i.qty, 0);
  const cartSubtotal = cartItems.reduce((s, i) => s + i.price * i.qty, 0);
  const cartShipping = cartItems.reduce((s, i) => s + (Number(i.shippingFee) || 0) * Number(i.qty || 1), 0);
  const cartTax = Math.round(cartSubtotal * (settings.taxRate || 0) * 100) / 100;
  const cartTotal = cartSubtotal + cartShipping + cartTax;
  const cartCurrency = "NGN";

  const persistOrders = async (next) => {
    setOrders(next);
    try {
      await window.storage.set("stallyard-orders", JSON.stringify(next), true);
    } catch {
      showToast("Couldn't save your order — try again");
    }
  };

  const persistSettings = async (next, field = null) => {
    const body = {};
    if (field === "commissionRate" || next.commissionRate !== settings.commissionRate) body.commissionRate = next.commissionRate;
    if (field === "taxRate" || next.taxRate !== settings.taxRate) body.taxRate = next.taxRate;
    if (next.authImage !== settings.authImage) body.authImage = next.authImage;
    if (Object.keys(body).length === 0) {
      // Older admin buttons pass the already-edited state without a field.
      if (hasAdminPermission(currentMember, "finance")) {
        body.commissionRate = next.commissionRate;
        body.taxRate = next.taxRate;
      } else {
        showToast("No settings changes to save");
        return false;
      }
    }
    showToast("Saving settings…");
    try {
      const res = await authFetch(`${BACKEND_URL}/settings`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't save settings — try again");
        return false;
      }
      setSettings({ commissionRate: data.commissionRate, taxRate: data.taxRate || 0, authImage: data.authImage || "" });
      showToast("Settings saved");
      return true;
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    }
  };

  const persistWithdrawals = async (next) => {
    setWithdrawals(next);
    try {
      await window.storage.set("stallyard-withdrawals", JSON.stringify(next), true);
    } catch {
      showToast("Couldn't save — try again");
    }
  };

  const persistThreads = async (next) => {
    setThreads(next);
    try {
      await window.storage.set("stallyard-messages", JSON.stringify(next), true);
    } catch {
      showToast("Couldn't send — try again");
    }
  };

  const markThreadRead = async (threadId) => {
    const next = { ...messageReadState, [threadId]: Date.now() };
    setMessageReadState(next);
    try {
      await window.storage.set("stallyard-message-reads", JSON.stringify(next), false);
    } catch {
      // non-critical, fail silently
    }
  };

  const persistReviews = async (next) => {
    setReviews(next);
    try {
      await window.storage.set("stallyard-reviews", JSON.stringify(next), true);
    } catch {
      showToast("Couldn't save your review — try again");
    }
  };

  const submitReview = async (orderId, itemId, listingId, sellerUsername, rating, comment) => {
    if (!rating) {
      showToast("Pick a star rating");
      return;
    }
    const existing = reviews.find((r) => r.orderId === orderId && r.listingId === listingId);
    if (existing) {
      let res;
      try {
        res = await authFetch(`${BACKEND_URL}/reviews/${existing.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rating, comment: comment.trim() }),
        });
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
      if (!res.ok) {
        showToast("Couldn't update your review — try again");
        return;
      }
      const { review: row } = await res.json();
      await persistReviews(
        reviews.map((r) => (r.id === existing.id ? backendReviewToFrontend(row, members) : r))
      );
      showToast("Review updated");
    } else {
      const seller = members.find((m) => m.username === sellerUsername);
      if (!seller?.backendId) {
        showToast("Couldn't post that review — try again");
        return;
      }
      let res;
      try {
        res = await authFetch(`${BACKEND_URL}/reviews`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            orderId,
            listingId,
            sellerId: seller.backendId,
            rating,
            comment: comment.trim(),
          }),
        });
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't post that review");
        return;
      }
      const review = backendReviewToFrontend(data.review, members);
      await persistReviews([review, ...reviews]);
      showToast("Review posted");
    }
  };

  const startOrOpenThread = async (listing, orderId = null) => {
    if (!currentUser) {
      setCartOpen(false);
      setSelected(null);
      setAuthMode("login");
      setAuthError("");
      setAuthReturnView(view);
      setView("signin");
      showToast("Log in to message a seller");
      return;
    }
    if (listing.ownerUsername === currentUser) {
      showToast("That's your own listing");
      return;
    }
    const existing = threads.find(
      (t) => t.listingId === listing.id && t.buyerUsername === currentUser && t.sellerUsername === listing.ownerUsername
    );
    let threadId = existing?.id;
    if (!existing) {
      const seller = members.find((m) => m.username === listing.ownerUsername);
      if (!currentMember?.backendId || !seller?.backendId) {
        showToast("Couldn't start that conversation — try again");
        return;
      }
      let res;
      try {
        res = await authFetch(`${BACKEND_URL}/threads`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            listingId: listing.id,
            buyerId: currentMember.backendId,
            sellerId: seller.backendId,
          }),
        });
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
      if (!res.ok) {
        showToast("Couldn't start that conversation — try again");
        return;
      }
      const { thread } = await res.json();
      const newThread = backendThreadToFrontend(thread, [], members, listings);
      await persistThreads([newThread, ...threads]);
      threadId = newThread.id;
    }
    setSelected(null);
    setActiveThreadId(threadId);
    setActiveThreadOrderId(orderId);
    markThreadRead(threadId);
    setView("messages");
  };

  const sendMessage = async (threadId, text, imageUrl = null) => {
    const trimmed = text.trim();
    if (!trimmed && !imageUrl) return;
    if (trimmed && containsContactInfo(trimmed)) {
      setMessageError("Messages can't include email addresses or phone numbers — keep contact on Stallyard.");
      return;
    }
    setMessageError("");
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threadId,
          body: trimmed,
          messageType: "text",
          imageUrl: imageUrl || undefined,
          orderId: activeThreadOrderId || undefined,
        }),
      });
    } catch {
      setMessageError("Couldn't reach the server — try again.");
      return;
    }
    if (!res.ok) {
      setMessageError("Couldn't send that — try again.");
      return;
    }
    const { message: row } = await res.json();
    const message = backendMessageToFrontend(row, members);
    await persistThreads(
      threads.map((t) =>
        t.id === threadId ? { ...t, messages: [...t.messages, message], updatedAt: Date.now() } : t
      )
    );
    setMessageInput("");
  };

  const handleMessagePhotoSelect = async (e, threadId) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      showToast("That photo is too large — please upload something under 5MB");
      return;
    }
    setUploadingMessagePhoto(true);
    try {
      const dataUrl = await resizeImageFile(file, 1200, 0.8);
      await sendMessage(threadId, "", dataUrl);
    } catch {
      showToast("Couldn't send that photo — try again");
    } finally {
      setUploadingMessagePhoto(false);
    }
  };

  const reportMessage = async (messageId, reason) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/messages/${messageId}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason || "" }),
      });
      if (!res.ok) {
        showToast("Couldn't submit that report — try again");
        return;
      }
      showToast("Reported — an admin will take a look");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminResolveMessageReport = async (reportId) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/message-reports/${reportId}/resolve`, { method: "PATCH" });
      if (!res.ok) {
        showToast("Couldn't resolve that report — try again");
        return;
      }
      setMessageReports((reports) =>
        reports.map((r) => (r.id === reportId ? { ...r, status: "resolved" } : r))
      );
      showToast("Report resolved");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const respondToReview = async (reviewId, response) => {
    if (!response.trim()) {
      showToast("Write a response first");
      return;
    }
    try {
      const res = await authFetch(`${BACKEND_URL}/reviews/${reviewId}/respond`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: response.trim() }),
      });
      if (!res.ok) {
        showToast("Couldn't save your response — try again");
        return;
      }
      setReviews((rs) =>
        rs.map((r) =>
          r.id === reviewId ? { ...r, sellerResponse: response.trim(), sellerResponseAt: Date.now() } : r
        )
      );
      setReviewResponseDrafts((d) => {
        const next = { ...d };
        delete next[reviewId];
        return next;
      });
      showToast("Response posted");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const reportReview = async (reviewId, reason) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/reviews/${reviewId}/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason || "" }),
      });
      if (!res.ok) {
        showToast("Couldn't submit that report — try again");
        return;
      }
      showToast("Reported — an admin will take a look");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminResolveReviewReport = async (reportId) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/review-reports/${reportId}/resolve`, { method: "PATCH" });
      if (!res.ok) {
        showToast("Couldn't resolve that report — try again");
        return;
      }
      setReviewReports((reports) =>
        reports.map((r) => (r.id === reportId ? { ...r, status: "resolved" } : r))
      );
      showToast("Report resolved");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminResolveAccountReport = async (reportId) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/account-reports/${reportId}/resolve`, { method: "PATCH" });
      if (!res.ok) {
        showToast("Couldn't resolve that report — try again");
        return;
      }
      setAccountReports((reports) =>
        reports.map((r) => (r.id === reportId ? { ...r, status: "resolved" } : r))
      );
      showToast("Report resolved");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const openSellerReport = (sellerId, sellerName, orderId = null) => {
    if (!currentUser) {
      setAuthReturnView(view);
      setView("login");
      return;
    }
    setSellerReportTarget({ sellerId, sellerName, orderId });
    setSellerReportForm({ reason: "", details: "", evidenceUrls: [] });
  };

  const addSellerReportEvidence = async (event) => {
    const files = Array.from(event.target.files || []).slice(0, 5 - sellerReportForm.evidenceUrls.length);
    const valid = files.filter((file) => file.type.startsWith("image/") && file.size <= 2 * 1024 * 1024);
    if (valid.length !== files.length) showToast("Evidence must be images no larger than 2 MB each");
    const urls = await Promise.all(valid.map(readFileAsDataURL));
    setSellerReportForm((form) => ({ ...form, evidenceUrls: [...form.evidenceUrls, ...urls].slice(0, 5) }));
    event.target.value = "";
  };

  const submitSellerReport = async () => {
    if (!sellerReportForm.reason) return showToast("Choose why you are reporting this seller");
    if (sellerReportForm.details.trim().length < 10) return showToast("Please explain what happened in at least 10 characters");
    setSubmittingSellerReport(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/seller-reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sellerId: sellerReportTarget.sellerId,
          orderId: sellerReportTarget.orderId,
          reason: sellerReportForm.reason,
          details: sellerReportForm.details.trim(),
          evidenceUrls: sellerReportForm.evidenceUrls,
        }),
      });
      const data = await res.json();
      if (!res.ok) return showToast(data.error || "Couldn't submit the seller report");
      setSellerReportTarget(null);
      setSellerReportReceipt(data.report.reference);
      showToast(`Report submitted — reference ${data.report.reference}`);
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSubmittingSellerReport(false);
    }
  };

  const updateSellerReport = async (reportId, status) => {
    const adminNote = window.prompt("Internal review note (optional)") || "";
    try {
      const res = await authFetch(`${BACKEND_URL}/seller-reports/${reportId}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status, adminNote }),
      });
      const data = await res.json();
      if (!res.ok) return showToast(data.error || "Couldn't update seller report");
      setSellerReports((reports) => reports.map((report) => report.id === reportId ? { ...report, ...data.report } : report));
      showToast(`Seller report marked ${status.replace("_", " ")}`);
    } catch { showToast("Couldn't reach the server — try again"); }
  };

  const fetchAdminLocalDeliveries = async () => {
    setLocalDeliveryLoading(true);
    try {
      const [deliveriesRes, reportsRes] = await Promise.all([
        authFetch(`${BACKEND_URL}/admin/local-deliveries`),
        authFetch(`${BACKEND_URL}/admin/local-driver-reports`),
      ]);
      const deliveriesData = await deliveriesRes.json().catch(() => ({}));
      const reportsData = await reportsRes.json().catch(() => ({}));
      if (!deliveriesRes.ok) return showToast(deliveriesData.error || "Couldn't load local deliveries");
      if (!reportsRes.ok) return showToast(reportsData.error || "Couldn't load driver reports");
      setAdminLocalDeliveries(deliveriesData.deliveries || []);
      setLocalDriverReports(reportsData.reports || []);
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setLocalDeliveryLoading(false);
    }
  };

  const updateLocalDriverReport = async (reportId, status) => {
    const adminNote = window.prompt("Internal review note (optional)") || "";
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/local-driver-reports/${reportId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status, adminNote }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.report) return showToast(data.error || "Couldn't update the driver report");
      setLocalDriverReports((reports) => reports.map((report) => report.id === reportId ? { ...report, ...data.report } : report));
      await fetchAdminLocalDeliveries();
      showToast(`Driver report marked ${status.replace("_", " ")}`);
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminRevokeLocalDelivery = async (assignmentId) => {
    const reason = window.prompt("Why are you revoking this driver's delivery access?") || "";
    if (reason.trim().length < 5) return reason && showToast("Enter at least 5 characters");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/local-deliveries/${assignmentId}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return showToast(data.error || "Couldn't revoke driver access");
      setAdminLocalDeliveries((deliveries) => deliveries.map((delivery) =>
        delivery.id === assignmentId ? { ...delivery, status: "revoked", revokedAt: new Date().toISOString() } : delivery
      ));
      showToast("Driver access revoked and recorded in the audit log");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const openAdminPanel = () => {
    if (!isAdminHost()) {
      window.location.assign(ADMIN_URL);
      return;
    }
    // Never show the buyer/seller marketplace underneath the admin gate.
    setView("admin");
    if (adminUnlockedUntil && Date.now() < adminUnlockedUntil) {
      return;
    }
    // If password/authenticator/email verification is already underway,
    // do not restart it. This protects Step 2 and Step 3 from background
    // effects or repeated clicks resetting the modal to the password step.
    if (adminReauthStep) return;
    setAdminReauthStep("password");
    setAdminReauthPassword("");
    setAdminReauthCode("");
    setAdminReauthError("");
  };

  const submitAdminReauthPassword = async () => {
    if (!adminReauthPassword) {
      setAdminReauthError("Enter your password");
      return;
    }
    setAdminReauthSubmitting(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/reauth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: adminReauthPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAdminReauthError(data.error || "Couldn't verify your password");
        return;
      }
      if (!data.twoFactorRequired || data.method !== "totp") {
        setAdminReauthError("Admin multi-factor authentication is required. Contact the super admin if your authenticator is not configured.");
        return;
      }
      setAdminReauthStep("code");
      setAdminReauthError("");
    } catch {
      setAdminReauthError("Couldn't reach the server — try again");
    } finally {
      setAdminReauthSubmitting(false);
    }
  };

  // Handles both steps of the reauth gate: authenticator app first
  // (adminReauthStep === "code"), then the auto-sent email code
  // (adminReauthStep === "code-email"). Both are mandatory.
  const submitAdminReauthCode = async () => {
    if (!adminReauthCode.trim()) {
      setAdminReauthError(
        adminReauthStep === "code-email" ? "Enter the code we emailed you" : "Enter the code from your authenticator app"
      );
      return;
    }
    setAdminReauthSubmitting(true);
    const endpoint = adminReauthStep === "code-email" ? "/admin/reauth/verify-email" : "/admin/reauth/verify";
    try {
      const res = await authFetch(`${BACKEND_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: adminReauthCode.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAdminReauthError(data.error || "That code didn't work");
        return;
      }
      if (data.emailStepRequired) {
        setAdminReauthStep("code-email");
        setAdminReauthCode("");
        showToast("Authenticator code confirmed — check your email for the next code");
        return;
      }
      setAdminUnlockedUntil(Date.now() + ADMIN_SESSION_IDLE_MS);
      setAdminReauthStep(null);
      setView("admin");
    } catch {
      setAdminReauthError("Couldn't reach the server — try again");
    } finally {
      setAdminReauthSubmitting(false);
    }
  };

  // Shared by both steps of the dedicated admin login: if the account
  // isn't actually an admin, the error is identical to a wrong password —
  // never confirms that valid, non-admin credentials were entered. A
  // successful admin login here also satisfies the re-auth gate, since
  // proving password + 2FA to log in already covers what re-auth checks.
  const finishAdminLogin = async (data, username) => {
    if (!data.user?.is_admin) {
      setAdminLoginError("Username or password doesn't match");
      return;
    }
    await completeLogin(data, username);
    setAdminUnlockedUntil(Date.now() + ADMIN_SESSION_IDLE_MS);
    setAdminLoginMode(false);
    setAdminLoginForm({ username: "", password: "" });
    setAdminLoginStep("credentials");
    setAdminLoginCode("");
    window.history.replaceState({}, "", "/");
    setView("admin");
  };

  const submitAdminLoginCredentials = async () => {
    const username = adminLoginForm.username.trim().toLowerCase();
    if (!username || !adminLoginForm.password) {
      setAdminLoginError("Enter your username and password");
      return;
    }
    setAdminLoginSubmitting(true);
    setAdminLoginError("");
    try {
      const res = await backendFetch(`${BACKEND_URL}/admin/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password: adminLoginForm.password }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.code === "ADMIN_MFA_REQUIRED" || data.code === "ADMIN_EMAIL_REQUIRED") {
          setAdminLoginError(data.error);
        } else {
          setAdminLoginError("Username or password doesn't match");
        }
        return;
      }
      if (!data.twoFactorRequired || data.method !== "totp") {
        setAdminLoginError("Admin multi-factor authentication is required");
        return;
      }
      setAdminLoginPendingUserId(data.userId);
      setAdminLoginStep("code");
      return;
    } catch {
      setAdminLoginError("Couldn't reach the server — try again");
    } finally {
      setAdminLoginSubmitting(false);
    }
  };

  // Handles both steps of the dedicated admin login's 2FA: authenticator
  // app first (adminLoginStep === "code"), then the auto-sent email code
  // (adminLoginStep === "code-email"). Both are mandatory.
  const submitAdminLoginTwoFactor = async () => {
    if (!adminLoginCode.trim()) {
      setAdminLoginError(
        adminLoginStep === "code-email" ? "Enter the code we emailed you" : "Enter the code from your authenticator app"
      );
      return;
    }
    setAdminLoginSubmitting(true);
    setAdminLoginError("");
    const endpoint = adminLoginStep === "code-email" ? "/login/verify-2fa-email" : "/login/verify-2fa";
    try {
      const res = await backendFetch(`${BACKEND_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: adminLoginPendingUserId, code: adminLoginCode.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAdminLoginError(data.error || "That code didn't work");
        return;
      }
      if (data.emailStepRequired) {
        setAdminLoginStep("code-email");
        setAdminLoginCode("");
        showToast("Authenticator code confirmed — check your email for the next code");
        return;
      }
      if (data.temporaryPasswordChangeRequired) {
        setAdminTempPasswordChangeToken(data.passwordChangeToken || "");
        setAdminTempNewPasswordForm({ password: "", confirm: "" });
        setAdminLoginCode("");
        setAdminLoginStep("new-password");
        return;
      }
      await finishAdminLogin(data, adminLoginForm.username.trim().toLowerCase());
    } catch {
      setAdminLoginError("Couldn't reach the server — try again");
    } finally {
      setAdminLoginSubmitting(false);
    }
  };

  const completeAdminTemporaryPassword = async () => {
    const password = adminTempNewPasswordForm.password;
    if (password.length < 8) {
      setAdminLoginError("New password must be at least 8 characters");
      return;
    }
    if (password !== adminTempNewPasswordForm.confirm) {
      setAdminLoginError("Passwords don't match");
      return;
    }
    if (!adminTempPasswordChangeToken) {
      setAdminLoginError("Temporary-password recovery expired — ask the Super Admin for a new temporary password");
      return;
    }
    setAdminLoginSubmitting(true);
    setAdminLoginError("");
    try {
      const res = await backendFetch(`${BACKEND_URL}/admin/temporary-password/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          passwordChangeToken: adminTempPasswordChangeToken,
          newPassword: password,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setAdminLoginError(data.error || "Couldn't set your new password");
        return;
      }
      setAdminTempPasswordChangeToken("");
      setAdminTempNewPasswordForm({ password: "", confirm: "" });
      await finishAdminLogin(data, data.user?.username || adminLoginForm.username.trim().toLowerCase());
      showToast("Permanent admin password set — you're signed in");
    } catch {
      setAdminLoginError("Couldn't reach the server — try again");
    } finally {
      setAdminLoginSubmitting(false);
    }
  };

  const fetchAuditLog = async () => {
    setLoadingAuditLog(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin-audit-log`);
      if (res.ok) {
        const { log } = await res.json();
        setAuditLog(log);
      }
    } catch {
      showToast("Couldn't load the audit log — try again");
    } finally {
      setLoadingAuditLog(false);
    }
  };

  const fetchAdminStaff = async () => {
    setLoadingAdminStaff(true);
    setAdminStaffError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/staff`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setAdminStaffError(data.error || "Couldn't load admin staff");
        return;
      }
      setAdminStaff(Array.isArray(data.staff) ? data.staff : []);
    } catch {
      setAdminStaffError("Couldn't reach the server — try again");
    } finally {
      setLoadingAdminStaff(false);
    }
  };

  const fetchSystemHealth = async () => {
    setSystemHealthLoading(true);
    setSystemHealthError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/system-health`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setSystemHealthError(data.error || "Couldn't load system health");
        return;
      }
      setSystemHealth(data);
    } catch {
      setSystemHealthError("Couldn't reach the backend — try again");
    } finally {
      setSystemHealthLoading(false);
    }
  };

  const fetchAdminReport = async (type = adminReportType) => {
    setAdminReportLoading(true);
    setAdminReportError("");
    setAdminReportData(null);
    try {
      const params = new URLSearchParams();
      if (adminReportFrom) params.set("from", adminReportFrom);
      if (adminReportTo) params.set("to", adminReportTo);
      const res = await authFetch(`${BACKEND_URL}/admin/reports/${encodeURIComponent(type)}?${params.toString()}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setAdminReportError(data.error || "Couldn't generate report");
        return;
      }
      setAdminReportData({
        ...data,
        columns: Array.isArray(data.columns) ? data.columns : [],
        rows: Array.isArray(data.rows) ? data.rows : [],
        summary: data.summary && typeof data.summary === "object" ? data.summary : {},
      });
    } catch {
      setAdminReportError("Couldn't reach the server — try again");
    } finally {
      setAdminReportLoading(false);
    }
  };

  const downloadAdminReportCsv = () => {
    const data = adminReportData;
    if (!data?.rows?.length || !data?.columns?.length) {
      showToast("Generate a report with data first");
      return;
    }
    const escapeCell = (value) => {
      if (value === null || value === undefined) return "";
      const raw = value instanceof Date ? value.toISOString() : String(value);
      return /[",\n\r]/.test(raw) ? `"${raw.replace(/"/g, '""')}"` : raw;
    };
    const lines = [
      data.columns.map(escapeCell).join(","),
      ...data.rows.map((row) => data.columns.map((c) => escapeCell(row?.[c])).join(",")),
    ];
    const blob = new Blob(["\uFEFF" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const range = `${data.from || "all"}_${data.to || "now"}`;
    a.href = url;
    a.download = `stallyard-${data.type || adminReportType}-${range}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast("CSV downloaded");
  };

  const revokeAdminStaffSessions = async (staff) => {
    if (!staff?.id) return;
    if (staff.username === currentUser) {
      showToast("Use your own account security controls for your sessions");
      return;
    }
    if (!window.confirm(`Sign ${staff.display_name || staff.username} out of all admin sessions?`)) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/staff/${staff.id}/revoke-sessions`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't revoke sessions");
        return;
      }
      showToast("Admin sessions revoked");
      await fetchAdminStaff();
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const generateAdminTemporaryPassword = async (staff) => {
    if (!staff?.id) return;
    if (staff.username === currentUser) {
      showToast("Use your own account security controls to change your password");
      return;
    }
    if (!staff.is_admin) {
      showToast("Temporary passwords are only for active admin accounts");
      return;
    }
    if (!window.confirm(`Issue a one-time 10-minute temporary password for ${staff.display_name || staff.username}? Their existing sessions will be revoked.`)) return;
    setAdminTempPasswordGeneratingId(staff.id);
    setAdminTempPasswordResult(null);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/staff/${staff.id}/temporary-password`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't generate a temporary password");
        return;
      }
      const result = {
        ...data,
        temporaryPassword: data.temporaryPassword || data.temporary_password || "",
        username: data.username || staff.username,
        expiresAt: data.expiresAt || data.expires_at || null,
      };
      setAdminTempPasswordResult(result);
      showToast("Temporary password generated — it expires in 10 minutes");
      // Native fallback: this makes the password visible even if a CSS/layout
      // issue prevents the styled modal from painting on a particular browser.
      if (result.temporaryPassword) {
        setTimeout(() => {
          window.prompt(
            `10-minute temporary password for @${result.username}. Copy it now — it will not be shown again after you close the password box.`,
            result.temporaryPassword
          );
        }, 0);
      }
      await fetchAdminStaff();
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setAdminTempPasswordGeneratingId(null);
    }
  };

  const sendAdminPasswordReset = async (staff) => {
    if (!staff?.id) return;
    if (staff.username === currentUser) {
      showToast("Use your own account security controls to change your password");
      return;
    }
    if (!staff.is_admin) {
      showToast("Password reset from Staff Management is only for active admin accounts");
      return;
    }
    if (!window.confirm(`Send a secure password-reset code to ${staff.display_name || staff.username}'s admin email and sign them out of existing sessions?`)) return;
    setAdminPasswordResettingId(staff.id);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/staff/${staff.id}/reset-password`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't start the password reset");
        return;
      }
      showToast(`Password reset sent to ${data.maskedEmail || "the admin's email"} — existing sessions were revoked`);
      await fetchAdminStaff();
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setAdminPasswordResettingId(null);
    }
  };

  const openAdminWarnings = async (member) => {
    setAdminWarningsTarget(member);
    setNewWarningMessage("");
    try {
      const res = await authFetch(`${BACKEND_URL}/users/${member.backendId}/warnings`);
      if (res.ok) {
        const { warnings } = await res.json();
        setAdminWarningsList(warnings);
      }
    } catch {
      showToast("Couldn't load warnings — try again");
    }
  };

  const issueWarning = async () => {
    if (!newWarningMessage.trim() || !adminWarningsTarget) {
      showToast("Write a message for the warning");
      return;
    }
    setIssuingWarning(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/users/${adminWarningsTarget.backendId}/warnings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: newWarningMessage.trim() }),
      });
      if (!res.ok) {
        showToast("Couldn't issue that warning — try again");
        return;
      }
      const { warning } = await res.json();
      setAdminWarningsList((list) => [warning, ...list]);
      setNewWarningMessage("");
      showToast("Warning issued");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setIssuingWarning(false);
    }
  };

  // Public trust signal — fetched on demand when a storefront opens, cached
  // per username so revisiting the same seller doesn't re-fetch.
  const fetchLoginHistory = async () => {
    if (loginHistory !== null) return;
    setLoadingLoginHistory(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/login-history/mine`);
      if (res.ok) {
        const { history } = await res.json();
        setLoginHistory(history);
      }
    } catch {
      // couldn't reach backend — leave as null, "Show" button just won't populate
    } finally {
      setLoadingLoginHistory(false);
    }
  };

  const fetchSellerSalesCount = async (username) => {
    if (sellerSalesCounts[username] !== undefined) return;
    try {
      const res = await backendFetch(`${BACKEND_URL}/sellers/${username}/completed-sales-count`);
      if (!res.ok) return;
      const { count } = await res.json();
      setSellerSalesCounts((c) => ({ ...c, [username]: count }));
    } catch {
      // couldn't reach backend — leave uncached, storefront just won't show a count
    }
  };

  const handleAvatarSelect = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      showToast("That photo is too large — please upload something under 5MB");
      return;
    }
    setUploadingAvatar(true);
    try {
      const dataUrl = await resizeImageFile(file, 500, 0.85);
      const res = await authFetch(`${BACKEND_URL}/profile/store`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ avatarUrl: dataUrl }),
      });
      if (!res.ok) {
        showToast("Couldn't save that photo — try again");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, avatarUrl: dataUrl } : m))
      );
      showToast("Profile photo updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setUploadingAvatar(false);
    }
  };

  const saveStoreProfile = async () => {
    try {
      const res = await authFetch(`${BACKEND_URL}/profile/store`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          storeBio: storeProfileDraft.storeBio,
          storePolicies: storeProfileDraft.storePolicies,
        }),
      });
      if (!res.ok) {
        showToast("Couldn't save your store profile — try again");
        return;
      }
      await persistMembers(
        members.map((m) =>
          m.username === currentUser
            ? { ...m, storeBio: storeProfileDraft.storeBio, storePolicies: storeProfileDraft.storePolicies }
            : m
        )
      );
      setEditingStoreProfile(false);
      showToast("Store profile updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const sendOffer = async (threadId, amount) => {
    const amt = Math.round(Number(amount) * 100) / 100;
    if (!amt || amt <= 0) {
      showToast("Enter an offer amount");
      return;
    }
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threadId, messageType: "offer", offerAmount: amt }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    if (!res.ok) {
      showToast("Couldn't send that offer — try again");
      return;
    }
    const { message: row } = await res.json();
    const message = backendMessageToFrontend(row, members);
    await persistThreads(
      threads.map((t) =>
        t.id === threadId ? { ...t, messages: [...t.messages, message], updatedAt: Date.now() } : t
      )
    );
    showToast(`Offer of ${formatMoney(amt, "NGN")} sent`);
  };

  const respondToOffer = async (threadId, messageId, status) => {
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/messages/${messageId}/offer`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    if (!res.ok) {
      showToast("Couldn't respond to that offer — try again");
      return;
    }
    await persistThreads(
      threads.map((t) =>
        t.id !== threadId
          ? t
          : {
              ...t,
              messages: t.messages.map((m) => (m.id === messageId ? { ...m, status } : m)),
              updatedAt: Date.now(),
            }
      )
    );
    showToast(status === "accepted" ? "Offer accepted" : "Offer declined");
  };

  const addBanner = async (data) => {
    if (!data.message.trim()) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/content/banners`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: data.message.trim(),
          tone: data.tone || "info",
          mediaType: data.mediaType || "none",
          imageUrl: data.mediaType === "image" ? data.imageUrl : "",
          videoUrl: data.mediaType === "video" ? data.videoUrl.trim() : "",
        }),
      });
      if (!res.ok) {
        showToast("Couldn't add that banner — try again");
        return;
      }
      const { banner: b } = await res.json();
      setContent((c) => ({
        ...c,
        banners: [
          { id: b.id, message: b.message, tone: b.tone, isActive: b.is_active, mediaType: b.media_type, imageUrl: b.image_url || "", videoUrl: b.video_url || "" },
          ...c.banners,
        ],
      }));
      showToast("Banner added");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const updateBanner = async (id, patch) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/content/banners/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        showToast("Couldn't update that banner — try again");
        return;
      }
      setContent((c) => ({
        ...c,
        banners: c.banners.map((b) => (b.id === id ? { ...b, ...patch } : b)),
      }));
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const removeBanner = async (id) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/content/banners/${id}`, { method: "DELETE" });
      if (!res.ok) {
        showToast("Couldn't remove that banner — try again");
        return;
      }
      setContent((c) => ({ ...c, banners: c.banners.filter((b) => b.id !== id) }));
      showToast("Banner removed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const addArticle = async (data) => {
    if (!data.title.trim() || !data.body.trim()) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/content/articles`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: data.title.trim(), body: data.body.trim() }),
      });
      if (!res.ok) {
        showToast("Couldn't publish that article — try again");
        return;
      }
      const { article: a } = await res.json();
      setContent((c) => ({
        ...c,
        articles: [{ id: a.id, title: a.title, body: a.body, updatedAt: Date.now() }, ...c.articles],
      }));
      showToast("Article published");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const updateArticle = async (id, patch) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/content/articles/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        showToast("Couldn't update that article — try again");
        return;
      }
      setContent((c) => ({
        ...c,
        articles: c.articles.map((a) => (a.id === id ? { ...a, ...patch, updatedAt: Date.now() } : a)),
      }));
      showToast("Article updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const removeArticle = async (id) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/content/articles/${id}`, { method: "DELETE" });
      if (!res.ok) {
        showToast("Couldn't remove that article — try again");
        return;
      }
      setContent((c) => ({ ...c, articles: c.articles.filter((a) => a.id !== id) }));
      showToast("Article removed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const addFaq = async (data) => {
    if (!data.question.trim() || !data.answer.trim()) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/content/faqs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: data.question.trim(), answer: data.answer.trim() }),
      });
      if (!res.ok) {
        showToast("Couldn't add that FAQ — try again");
        return;
      }
      const { faq } = await res.json();
      setContent((c) => ({ ...c, faqs: [...c.faqs, faq] }));
      showToast("FAQ added");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const updateFaq = async (id, patch) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/content/faqs/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        showToast("Couldn't update that FAQ — try again");
        return;
      }
      setContent((c) => ({
        ...c,
        faqs: c.faqs.map((f) => (f.id === id ? { ...f, ...patch } : f)),
      }));
      showToast("FAQ updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const removeFaq = async (id) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/content/faqs/${id}`, { method: "DELETE" });
      if (!res.ok) {
        showToast("Couldn't remove that FAQ — try again");
        return;
      }
      setContent((c) => ({ ...c, faqs: c.faqs.filter((f) => f.id !== id) }));
      showToast("FAQ removed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const savePolicy = async (category, body) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/policies/${category}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body }),
      });
      if (!res.ok) {
        showToast("Couldn't save that policy — try again");
        return;
      }
      setPolicies((p) => ({ ...p, [category]: body }));
      showToast("Policy updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const fetchMyTickets = async () => {
    try {
      const res = await authFetch(`${BACKEND_URL}/support-tickets/mine`);
      if (res.ok) {
        const { tickets } = await res.json();
        setMyTickets(tickets);
      }
    } catch {
      // couldn't reach backend — leave whatever was already loaded
    }
  };

  const createSupportTicket = async () => {
    if (!newTicketForm.subject.trim() || !newTicketForm.message.trim()) {
      showToast("Give it a subject and a message");
      return;
    }
    setCreatingTicket(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/support-tickets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subject: newTicketForm.subject.trim(), message: newTicketForm.message.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't open that ticket — try again");
        return;
      }
      setMyTickets((t) => [data.ticket, ...t]);
      setNewTicketForm({ subject: "", message: "" });
      setShowNewTicketForm(false);
      showToast("Ticket opened — we'll get back to you here");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setCreatingTicket(false);
    }
  };

  const openTicketThread = (ticketId) => setActiveTicketId(ticketId);
  useEffect(() => {
    if (!activeTicketId || !currentUser || !sessionChecked) return;
    let cancelled = false;
    setTicketMessages([]);
    setLoadingTicketMessages(true);
    (async () => {
      try {
        const res = await authFetch(`${BACKEND_URL}/support-tickets/${activeTicketId}/messages`);
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) setTicketMessages(data.messages || []);
        } else if (!cancelled) showToast("This support conversation is unavailable");
      } catch { if (!cancelled) showToast("Couldn't load that conversation — try again"); }
      finally { if (!cancelled) setLoadingTicketMessages(false); }
    })();
    return () => { cancelled = true; };
  }, [activeTicketId, currentUser, sessionChecked]);

  const sendTicketMessage = async () => {
    if (!newTicketMessageInput.trim() || !activeTicketId) return;
    setSendingTicketMessage(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/support-tickets/${activeTicketId}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: newTicketMessageInput.trim() }),
      });
      if (!res.ok) {
        showToast("Couldn't send that — try again");
        return;
      }
      const { message } = await res.json();
      setTicketMessages((m) => [...m, message]);
      setNewTicketMessageInput("");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSendingTicketMessage(false);
    }
  };

  const openAdminNotes = async (entityType, entityId, label) => {
    if (!entityId) {
      showToast("This record is missing its server ID");
      return;
    }
    setAdminNotesTarget({ entityType, entityId, label });
    setAdminNoteDraft("");
    setAdminNotesList([]);
    setAdminNotesLoading(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin-notes/${entityType}/${entityId}`);
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't load internal notes");
        setAdminNotesTarget(null);
        return;
      }
      setAdminNotesList(data.notes || []);
    } catch {
      showToast("Couldn't reach the server — try again");
      setAdminNotesTarget(null);
    } finally {
      setAdminNotesLoading(false);
    }
  };

  const addAdminNote = async () => {
    if (!adminNotesTarget || !adminNoteDraft.trim()) return;
    setAdminNoteSaving(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin-notes/${adminNotesTarget.entityType}/${adminNotesTarget.entityId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: adminNoteDraft.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't save internal note");
        return;
      }
      setAdminNotesList((notes) => [data.note, ...notes]);
      setAdminNoteDraft("");
      showToast("Internal note saved");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setAdminNoteSaving(false);
    }
  };

  const fetchAdminTickets = async () => {
    try {
      const res = await authFetch(`${BACKEND_URL}/support-tickets`);
      if (res.ok) {
        const { tickets } = await res.json();
        setAdminTickets(tickets);
      }
    } catch {
      // couldn't reach backend — leave whatever was already loaded
    }
  };

  const adminUpdateTicketStatus = async (ticketId, status) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/support-tickets/${ticketId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (!res.ok) {
        showToast("Couldn't update that ticket — try again");
        return;
      }
      setAdminTickets((tickets) => tickets.map((t) => (t.id === ticketId ? { ...t, status } : t)));
      showToast("Ticket status updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const fileDispute = async (orderId) => {
    const reason = window.prompt(
      "What is the main problem with this order? For example: item not received, damaged, wrong item, counterfeit, or not as described."
    );
    if (reason === null) return;
    if (!reason.trim()) {
      showToast("Enter a reason before opening a dispute");
      return;
    }
    const statement = window.prompt(
      "Briefly explain what happened. This statement will be part of the dispute case for the admin to review."
    );
    if (statement === null) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/orders/${orderId}/dispute`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isDisputed: true, reason: reason.trim(), statement: statement.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't open the dispute — try again");
        return;
      }
      await persistOrders(orders.map((o) => (o.id === orderId ? { ...o, isDisputed: true } : o)));
      if (data.dispute) {
        setMyDisputes((cases) => [data.dispute, ...cases.filter((d) => d.id !== data.dispute.id)]);
      }
      showToast("Dispute opened — payment is locked while the case is reviewed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const patchOrderOnBackend = async (orderId, action, body) => {
    if (typeof orderId !== "number") return { legacy: true }; // legacy local-only order, nothing to sync
    try {
      const res = await authFetch(`${BACKEND_URL}/orders/${orderId}/${action}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't save that change — try again");
        return false;
      }
      return data;
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    }
  };

  const patchOrderItemOnBackend = async (itemId, body) => {
    if (typeof itemId !== "number") return true;
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't save that change — try again");
        return false;
      }
      return true;
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    }
  };

  const respondToDispute = async (disputeId) => {
    const statement = window.prompt("Enter your statement for the dispute administrator. Be specific about what happened.");
    if (statement === null) return;
    if (!statement.trim()) {
      showToast("Enter a statement first");
      return;
    }
    try {
      const res = await authFetch(`${BACKEND_URL}/disputes/${disputeId}/statement`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ statement: statement.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't save your statement");
        return;
      }
      setMyDisputes((cases) => cases.map((d) => (d.id === disputeId ? { ...d, ...data.dispute } : d)));
      showToast("Statement added to the dispute case");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const saveAdminDisputeCase = async (dispute) => {
    const draft = disputeAdminDrafts[dispute.id] || {};
    setSavingDisputeCaseId(dispute.id);
    try {
      const res = await authFetch(`${BACKEND_URL}/disputes/${dispute.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: draft.status ?? dispute.status,
          resolution: draft.resolution ?? dispute.resolution ?? "",
          resolutionNote: draft.resolutionNote ?? dispute.resolution_note ?? "",
          adminNotes: draft.adminNotes ?? dispute.admin_notes ?? "",
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't update the dispute case");
        return;
      }
      setAdminDisputes((cases) => cases.map((d) => (d.id === dispute.id ? { ...d, ...data.dispute } : d)));
      setOrders((os) => os.map((o) => (o.id === dispute.order_id ? { ...o, isDisputed: data.dispute.status !== "resolved" } : o)));
      setDisputeAdminDrafts((all) => {
        const next = { ...all };
        delete next[dispute.id];
        return next;
      });
      showToast(data.dispute.status === "resolved" ? "Dispute resolved and payment lock updated" : "Dispute case updated");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSavingDisputeCaseId(null);
    }
  };

  const releasePayout = async (orderId) => {
    const sendRelease = async (body) => {
      try {
        const res = await authFetch(`${BACKEND_URL}/orders/${orderId}/release`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: body ? JSON.stringify(body) : undefined,
        });
        const data = await res.json().catch(() => ({}));
        return { res, data };
      } catch {
        return { res: null, data: { error: "Couldn't reach the server — try again" } };
      }
    };

    let result = await sendRelease();
    if (!result.res) {
      showToast(result.data.error);
      return;
    }

    // Normal finance release is allowed only when the same proof + buyer-token
    // safeguards used by the seller flow are complete. If they are not, make
    // the admin consciously enter an emergency override instead of silently
    // bypassing delivery protection.
    if (!result.res.ok && result.data.code === "DELIVERY_SAFEGUARDS_REQUIRED") {
      const problems = Array.isArray(result.data.safeguardProblems)
        ? result.data.safeguardProblems
        : [];
      const warning = [
        "OVERRIDE DELIVERY SAFEGUARDS?",
        "",
        "Normal release is blocked because:",
        ...(problems.length ? problems.map((p) => `• ${p}`) : ["• Required delivery proof is incomplete"]),
        "",
        "An override releases real seller funds without the normal buyer-token and/or delivery-picture proof. Active returns still cannot be overridden.",
        "",
        "Continue only for an exceptional case you have independently reviewed.",
      ].join("\n");
      if (!window.confirm(warning)) return;

      const overrideReason = window.prompt(
        "Document why this emergency payment release is justified. This reason is written permanently to the admin audit log (minimum 10 characters)."
      );
      if (overrideReason === null) return;
      if (overrideReason.trim().length < 10) {
        showToast("Enter a clear override reason of at least 10 characters");
        return;
      }

      result = await sendRelease({
        overrideDeliverySafeguards: true,
        overrideReason: overrideReason.trim(),
      });
    }

    if (!result.res?.ok) {
      showToast(result.data.error || "Couldn't release that payment");
      return;
    }

    const data = result.data;
    await persistOrders(
      orders.map((o) =>
        o.id === orderId
          ? {
              ...o,
              paymentStatus: "released",
              isDisputed: data.order ? !!data.order.is_disputed : false,
            }
          : o
      )
    );
    if (data.resolvedDispute?.id) {
      setAdminDisputes((cases) =>
        cases.map((d) =>
          d.id === data.resolvedDispute.id ? { ...d, ...data.resolvedDispute } : d
        )
      );
    }
    if (data.deliverySafeguardsOverridden) {
      showToast("Payment released with an audited delivery-safeguard override");
    } else if (data.resolvedDispute?.id) {
      showToast("Seller payment released and dispute resolved together");
    } else {
      showToast("Payout marked as released");
    }
  };

  const fetchReconciliation = async () => {
    setReconciliationLoading(true);
    setReconciliationError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/reconciliation`);
      const data = await res.json();
      if (!res.ok) {
        setReconciliationError(data.error || "Couldn't load reconciliation data");
        return;
      }
      setReconciliationData({
        ...data,
        byCurrency: Array.isArray(data?.byCurrency) ? data.byCurrency : [],
        records: Array.isArray(data?.records) ? data.records.map((r) => ({
          ...r,
          flags: Array.isArray(r?.flags) ? r.flags : [],
        })) : [],
        withdrawals: data?.withdrawals && typeof data.withdrawals === "object" ? data.withdrawals : {},
        alerts: data?.alerts && typeof data.alerts === "object" ? data.alerts : {},
      });
    } catch {
      setReconciliationError("Couldn't reach the server — try again");
    } finally {
      setReconciliationLoading(false);
    }
  };

  const fetchSellerPerformance = async () => {
    setSellerPerformanceLoading(true);
    setSellerPerformanceError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/seller-performance`);
      const data = await res.json();
      if (!res.ok) {
        setSellerPerformanceError(data.error || "Couldn't load seller performance");
        return;
      }
      setSellerPerformanceData(data);
    } catch {
      setSellerPerformanceError("Couldn't reach the server — try again");
    } finally {
      setSellerPerformanceLoading(false);
    }
  };

  const fetchBuyerRisk = async () => {
    setBuyerRiskLoading(true);
    setBuyerRiskError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/buyer-risk`);
      const data = await res.json();
      if (!res.ok) {
        setBuyerRiskError(data.error || "Couldn't load buyer risk data");
        return;
      }
      setBuyerRiskData(data);
    } catch {
      setBuyerRiskError("Couldn't reach the server — try again");
    } finally {
      setBuyerRiskLoading(false);
    }
  };

  const fetchCasualSellerVerification = async () => {
    setCasualSellerAdminLoading(true);
    try {
      const [applicationsRes, reportsRes] = await Promise.all([
        authFetch(`${BACKEND_URL}/admin/casual-seller-applications`),
        authFetch(`${BACKEND_URL}/admin/casual-seller-reports`),
      ]);
      const applicationsData = await applicationsRes.json();
      const reportsData = await reportsRes.json();
      if (!applicationsRes.ok) throw new Error(applicationsData.error || "Couldn't load applications");
      if (!reportsRes.ok) throw new Error(reportsData.error || "Couldn't load reports");
      setCasualSellerApplications(applicationsData.applications || []);
      setCasualSellerReports(reportsData.reports || []);
    } catch (err) { showToast(err.message || "Couldn't load casual-seller verification"); }
    finally { setCasualSellerAdminLoading(false); }
  };

  const fetchVerifiedSellerApplications = async () => {
    const isSuperAdmin = currentMember?.isAdmin && (!currentMember.adminRole || currentMember.adminRole === "super_admin");
    if (!isSuperAdmin) {
      setVerifiedSellerApplications([]);
      return;
    }
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-applications`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Couldn't load verified-seller applications");
      setVerifiedSellerApplications(data.applications || []);
    } catch (err) { showToast(err.message || "Couldn't load verified-seller applications"); }
  };

  const fetchPremiumSellerApplications = async () => {
    const isSuperAdmin = currentMember?.isAdmin && (!currentMember.adminRole || currentMember.adminRole === "super_admin");
    if (!isSuperAdmin) { setPremiumSellerApplications([]); return; }
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-applications`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Couldn't load Premium Seller applications");
      setPremiumSellerApplications(data.applications || []);
    } catch (err) { showToast(err.message || "Couldn't load Premium Seller applications"); }
  };

  const viewPremiumSellerDocument = async (application) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-applications/${application.id}/document`);
      if (!response.ok) throw new Error("Supporting document unavailable");
      const url = URL.createObjectURL(await response.blob());
      window.open(url, "_blank", "noopener,noreferrer");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (err) { showToast(err.message); }
  };

  const decidePremiumSellerApplication = async (application, approve) => {
    const reason = approve ? "" : window.prompt("Reason for rejection");
    if (!approve && !reason) return;
    const approvedLimit = approve ? Number(window.prompt("Approved combined active-listing limit", String(application.requested_limit))) : null;
    if (approve && (!Number.isFinite(approvedLimit) || approvedLimit <= 20000000)) { showToast("Enter an approved limit above ₦20,000,000"); return; }
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-applications/${application.id}/${approve ? "approve" : "reject"}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(approve ? { approvedLimit } : { reason }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Application could not be updated");
      if (data.user) {
        await persistMembers(members.map((member) => member.username === application.username ? backendUserToMember(data.user, member) : member));
      }
      await fetchPremiumSellerApplications();
      showToast(approve ? "Premium Seller approved" : "Premium Seller application rejected");
    } catch (err) { showToast(err.message || "Couldn't reach the server"); }
  };

  const fetchVerifiedSellerReports = async () => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-reports`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Couldn't load Verified Seller reports");
      setVerifiedSellerReports(data.reports || []);
    } catch (err) { showToast(err.message || "Couldn't load Verified Seller reports"); }
  };

  const downloadVerifiedSellerReport = async (report) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-reports/${report.id}/download`);
      if (!response.ok) { const data = await response.json(); throw new Error(data.error || "Report unavailable"); }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `stallyard-verified-sellers-${String(report.report_date).slice(0, 10)}.pdf`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { showToast(err.message || "Couldn't download report"); }
  };

  const revealVerifiedSellerReportPassword = async (report) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-reports/${report.id}/password`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report password unavailable");
      window.alert(`Password for the ${String(report.report_date).slice(0, 10)} Verified Seller report:\n\n${data.password}\n\nKeep this password private.`);
    } catch (err) { showToast(err.message || "Couldn't reveal report password"); }
  };

  const runVerifiedSellerReportNow = async () => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-reports/run`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report could not be generated");
      await fetchVerifiedSellerReports();
      showToast(data.sent ? `Verified Seller report sent for ${data.applicationCount} approval(s)` : "No unreported Verified Seller approvals were found");
    } catch (err) { showToast(err.message || "Couldn't generate Verified Seller report"); }
  };

  const fetchPremiumSellerReports = async () => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-reports`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Couldn't load Premium Seller reports");
      setPremiumSellerReports(data.reports || []);
    } catch (err) { showToast(err.message || "Couldn't load Premium Seller reports"); }
  };

  const downloadPremiumSellerReport = async (report) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-reports/${report.id}/download`);
      if (!response.ok) throw new Error("Premium Seller report unavailable");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href=url; link.download=`stallyard-premium-sellers-${String(report.report_date).slice(0,10)}.pdf`; link.click();
      setTimeout(()=>URL.revokeObjectURL(url),1000);
    } catch (err) { showToast(err.message); }
  };

  const revealPremiumSellerReportPassword = async (report) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-reports/${report.id}/password`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report password unavailable");
      window.alert(`Password for the ${String(report.report_date).slice(0,10)} Premium Seller report:\n\n${data.password}\n\nKeep this password private.`);
    } catch (err) { showToast(err.message); }
  };

  const runPremiumSellerReportNow = async () => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/premium-seller-reports/run`,{method:"POST"});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report could not be generated");
      await fetchPremiumSellerReports();
      showToast(data.sent ? `Premium Seller report sent for ${data.applicationCount} approval(s)` : "No unreported Premium Seller approvals were found");
    } catch (err) { showToast(err.message); }
  };

  const viewVerifiedSellerBankStatement = async (application) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-applications/${application.id}/bank-statement`);
      if (!response.ok) throw new Error("Bank statement unavailable");
      const url = URL.createObjectURL(await response.blob());
      window.open(url, "_blank", "noopener,noreferrer");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (err) { showToast(err.message); }
  };

  const viewVerifiedSellerIdentification = async (application, side) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-applications/${application.id}/identification/${side}`);
      if (!response.ok) throw new Error("Identification image unavailable");
      const url = URL.createObjectURL(await response.blob());
      window.open(url, "_blank", "noopener,noreferrer");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (err) { showToast(err.message); }
  };

  useEffect(() => {
    if (adminTab === "members" && currentMember?.isAdmin && (!currentMember.adminRole || currentMember.adminRole === "super_admin")) {
      fetchVerifiedSellerApplications();
      fetchPremiumSellerApplications();
    } else if (adminTab === "members") {
      setVerifiedSellerApplications([]);
      setPremiumSellerApplications([]);
    }
  }, [adminTab, currentMember?.isAdmin, currentMember?.adminRole]);

  useEffect(() => {
    if (adminTab === "members" && currentMember?.isAdmin && (!currentMember.adminRole || currentMember.adminRole === "super_admin")) {
      fetchVerifiedSellerReports();
      fetchPremiumSellerReports();
    }
  }, [adminTab, currentMember?.isAdmin, currentMember?.adminRole]);

  useEffect(() => {
    if (adminTab === "casualVerification" && currentMember?.isAdmin && (!currentMember.adminRole || currentMember.adminRole === "super_admin")) {
      fetchCasualSellerVerification();
    }
  }, [adminTab, currentMember?.isAdmin, currentMember?.adminRole]);

  const openCasualApplicationEvidence = async (application) => {
    Object.values(casualEvidenceUrls).forEach((url) => URL.revokeObjectURL(url));
    setCasualEvidenceUrls({});
    setSelectedCasualApplication(application);
    const urls = {};
    for (const key of application.evidence_keys || []) {
      try {
        const response = await authFetch(`${BACKEND_URL}/admin/casual-seller-applications/${application.id}/evidence/${key}`);
        if (response.ok) urls[key] = URL.createObjectURL(await response.blob());
      } catch {}
    }
    setCasualEvidenceUrls(urls);
  };

  const downloadCasualSellerReport = async (report) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/casual-seller-reports/${report.id}/download`);
      if (!response.ok) { const data = await response.json(); throw new Error(data.error || "Report unavailable"); }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = url; link.download = `stallyard-casual-sellers-${String(report.report_date).slice(0, 10)}.pdf`; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { showToast(err.message || "Couldn't download report"); }
  };

  const revealCasualSellerReportPassword = async (report) => {
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/casual-seller-reports/${report.id}/password`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Report password unavailable");
      window.alert(`Password for the ${String(report.report_date).slice(0, 10)} Casual Seller report:\n\n${data.password}\n\nKeep this password private.`);
    } catch (err) { showToast(err.message || "Couldn't reveal report password"); }
  };

  const verifyPaystackReconciliation = async (orderId) => {
    setPaystackCheckingOrderId(orderId);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/reconciliation/orders/${orderId}/verify-paystack`);
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't verify this payment with Paystack");
        return;
      }
      setPaystackChecks((prev) => ({ ...prev, [orderId]: data }));
      showToast(data.matches ? "Paystack payment matches Stallyard" : "Mismatch found — review this order");
    } catch {
      showToast("Couldn't reach Paystack verification — try again");
    } finally {
      setPaystackCheckingOrderId(null);
    }
  };

  const refundOrder = async (orderId) => {
    const existingOrder = orders.find((o) => o.id === orderId);
    const reason = window.prompt(
      "Reason for this full refund (required). This is stored in the admin record and sent with the Paystack refund request.",
      existingOrder?.refundReason || ""
    );
    if (reason === null) return;
    if (!reason.trim()) {
      showToast("Enter a refund reason before sending money back");
      return;
    }
    if (!window.confirm("Send a full refund through Paystack for this order? This action submits real money back to the buyer.")) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/orders/${orderId}/refund`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't start the refund — try again");
        return;
      }
      const updated = backendOrderToFrontend({ ...data.order, items: orders.find((o) => o.id === orderId)?.items || [] });
      await persistOrders(
        orders.map((o) =>
          o.id === orderId
            ? { ...o, ...updated, items: o.items, paymentStatus: "refund_pending", refundStatus: data.order.refund_status || "pending" }
            : o
        )
      );
      showToast("Refund submitted to Paystack — waiting for processing confirmation");
    } catch {
      showToast("Couldn't reach the server — check the order before trying again");
    }
  };

  const partialRefundOrder = async (dispute, order, amountRaw, reason) => {
    const amount = Math.round(Number(amountRaw) * 100) / 100;
    if (!(amount > 0)) {
      showToast("Enter a valid partial refund amount");
      return;
    }
    if (!reason?.trim()) {
      showToast("Enter the negotiated outcome / reason first");
      return;
    }
    if (!window.confirm(`Send a REAL partial refund of ${formatMoney(amount, order.currency)} through Paystack? The remaining seller proceeds will be released only after Paystack confirms the refund.`)) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/orders/${order.id}/refund/partial`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ disputeId: dispute.id, amount, reason: reason.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't start the partial refund");
        return;
      }
      const updated = backendOrderToFrontend({ ...data.order, items: order.items || [] });
      setOrders((all) => all.map((o) => o.id === order.id ? { ...o, ...updated, items: o.items } : o));
      setDisputeCases((all) => all.map((d) => d.id === dispute.id
        ? { ...d, status: "in_review", resolution: "partial_refund", resolution_note: reason.trim() }
        : d));
      showToast(`Partial refund of ${formatMoney(amount, order.currency)} submitted — waiting for Paystack confirmation`);
    } catch {
      showToast("Couldn't reach the server — check Paystack before trying again");
    }
  };

  const updateItemFulfillment = async (orderId, itemId, status) => {
    const ok = await patchOrderItemOnBackend(itemId, { fulfillmentStatus: status });
    if (!ok) return;
    if (["delivered", "cancelled", "returned"].includes(status)) {
      const watchId = locationWatchersRef.current[itemId];
      if (watchId !== undefined) navigator.geolocation?.clearWatch(watchId);
      delete locationWatchersRef.current[itemId];
      delete locationLastSentRef.current[itemId];
    }
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) =>
                i.id === itemId
                  ? {
                      ...i,
                      fulfillmentStatus: status,
                      ...(["delivered", "cancelled", "returned"].includes(status) ? { liveLocationEnabled: false } : {}),
                      statusHistory: [...(i.statusHistory || []), { status, at: Date.now() }],
                    }
                  : i
              ),
            }
      )
    );
    showToast(`Marked as ${FULFILLMENT_LABEL[status] || status}`);
  };

  const updateItemTracking = async (orderId, itemId, trackingNumber) => {
    const ok = await patchOrderItemOnBackend(itemId, { trackingNumber });
    if (!ok) return;
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) => (i.id === itemId ? { ...i, trackingNumber } : i)),
            }
      )
    );
    showToast("Tracking number saved");
  };

  const updateEstimatedDelivery = async (orderId, itemId, estimatedDeliveryStart, estimatedDeliveryEnd) => {
    if (estimatedDeliveryStart && estimatedDeliveryEnd && estimatedDeliveryEnd < estimatedDeliveryStart) {
      showToast("Estimated delivery end cannot be earlier than the start date");
      return false;
    }
    const ok = await patchOrderItemOnBackend(itemId, { estimatedDeliveryStart, estimatedDeliveryEnd });
    if (!ok) return false;
    await persistOrders(
      orders.map((o) => o.id !== orderId ? o : {
        ...o,
        items: o.items.map((i) => i.id === itemId ? { ...i, estimatedDeliveryStart, estimatedDeliveryEnd } : i),
      })
    );
    showToast(estimatedDeliveryStart ? "Estimated delivery saved" : "Estimated delivery cleared");
    return true;
  };

  const saveSellerLocation = async (orderId, itemId, position) => {
    const location = {
      liveLocationEnabled: true,
      liveLocationLatitude: position.coords.latitude,
      liveLocationLongitude: position.coords.longitude,
      liveLocationAccuracy: position.coords.accuracy,
    };
    const ok = await patchOrderItemOnBackend(itemId, {
      liveLocationLatitude: location.liveLocationLatitude,
      liveLocationLongitude: location.liveLocationLongitude,
      liveLocationAccuracy: location.liveLocationAccuracy,
    });
    if (!ok) return false;
    const updatedAt = Date.now();
    setOrders((all) => all.map((o) => o.id !== orderId ? o : {
      ...o,
      items: o.items.map((i) => i.id === itemId ? {
        ...i,
        ...location,
        liveLocationUpdatedAt: updatedAt,
      } : i),
    }));
    return true;
  };

  const startSellerLocationSharing = (orderId, itemId) => {
    if (!navigator.geolocation) {
      showToast("Location sharing is not supported on this phone");
      return;
    }
    if (locationWatchersRef.current[itemId] !== undefined) return;
    const watchId = navigator.geolocation.watchPosition(
      async (position) => {
        const now = Date.now();
        if (now - (locationLastSentRef.current[itemId] || 0) < 15000) return;
        locationLastSentRef.current[itemId] = now;
        const saved = await saveSellerLocation(orderId, itemId, position);
        if (saved && !locationLastSentRef.current[`${itemId}-announced`]) {
          locationLastSentRef.current[`${itemId}-announced`] = now;
          showToast("Live delivery location is now shared with the buyer");
        }
      },
      (error) => {
        delete locationWatchersRef.current[itemId];
        showToast(error.code === 1 ? "Allow location access on your phone to start sharing" : "Unable to get your current location");
      },
      { enableHighAccuracy: true, maximumAge: 10000, timeout: 20000 },
    );
    locationWatchersRef.current[itemId] = watchId;
  };

  const stopSellerLocationSharing = async (orderId, itemId) => {
    const watchId = locationWatchersRef.current[itemId];
    if (watchId !== undefined) navigator.geolocation.clearWatch(watchId);
    delete locationWatchersRef.current[itemId];
    delete locationLastSentRef.current[itemId];
    const ok = await patchOrderItemOnBackend(itemId, { liveLocationEnabled: false });
    if (!ok) return;
    setOrders((all) => all.map((o) => o.id !== orderId ? o : {
      ...o,
      items: o.items.map((i) => i.id === itemId ? { ...i, liveLocationEnabled: false } : i),
    }));
    showToast("Location sharing stopped");
  };

  useEffect(() => () => {
    Object.values(locationWatchersRef.current).forEach((watchId) => navigator.geolocation?.clearWatch(watchId));
  }, []);

  const saveLocalDriverAssignment = async (itemId, draft) => {
    const driverName = String(draft?.driverName || "").trim();
    const driverPhone = String(draft?.driverPhone || "").trim();
    const deliveryFee = Number(draft?.deliveryFee);
    if (driverName.length < 2) {
      showToast("Enter the driver's full name");
      return;
    }
    if (!driverPhone) {
      showToast("Enter the driver's Nigerian phone number");
      return;
    }
    if (!Number.isFinite(deliveryFee) || deliveryFee <= 0) {
      showToast("Enter a delivery fee greater than ₦0");
      return;
    }
    setDeliveryAssignmentSavingKey(itemId);
    try {
      const body = {
        driverName,
        driverPhone,
        deliveryFee,
        paymentMethod: draft?.paymentMethod || "cash",
        pickupAt: draft?.pickupAt ? new Date(draft.pickupAt).toISOString() : null,
        deliveryDueAt: draft?.deliveryDueAt ? new Date(draft.deliveryDueAt).toISOString() : null,
        packageDescription: String(draft?.packageDescription || "").trim(),
      };
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/delivery-assignment`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.assignment) {
        showToast(data.error || "Couldn't create the driver assignment");
        return;
      }
      setDeliveryAssignments((all) => ({ ...all, [itemId]: data.assignment }));
      setDeliveryAssignmentSecrets((all) => ({
        ...all,
        [itemId]: {
          accessUrl: `${window.location.origin}${data.accessPath}`,
          activationCode: data.activationCode,
        },
      }));
      showToast("Driver assignment created — copy the link and activation code");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setDeliveryAssignmentSavingKey(null);
    }
  };

  const regenerateLocalDriverAccess = async (itemId, assignmentId) => {
    setDeliveryAssignmentSavingKey(itemId);
    try {
      const res = await authFetch(`${BACKEND_URL}/delivery-assignments/${assignmentId}/regenerate-access`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.assignment) {
        showToast(data.error || "Couldn't regenerate driver access");
        return;
      }
      setDeliveryAssignments((all) => ({ ...all, [itemId]: data.assignment }));
      setDeliveryAssignmentSecrets((all) => ({
        ...all,
        [itemId]: {
          accessUrl: `${window.location.origin}${data.accessPath}`,
          activationCode: data.activationCode,
        },
      }));
      showToast("A new driver link and activation code were created");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setDeliveryAssignmentSavingKey(null);
    }
  };

  const revokeLocalDriverAccess = async (itemId, assignmentId) => {
    if (!window.confirm("Revoke this driver's access to the delivery?")) return;
    setDeliveryAssignmentSavingKey(itemId);
    try {
      const res = await authFetch(`${BACKEND_URL}/delivery-assignments/${assignmentId}/revoke`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.assignment) {
        showToast(data.error || "Couldn't revoke driver access");
        return;
      }
      setDeliveryAssignments((all) => ({ ...all, [itemId]: data.assignment }));
      setDeliveryAssignmentSecrets((all) => {
        const next = { ...all };
        delete next[itemId];
        return next;
      });
      showToast("Driver access revoked");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setDeliveryAssignmentSavingKey(null);
    }
  };

  const markLocalDriverPaid = async (itemId, assignment) => {
    const method = assignment?.paymentMethod === "bank_transfer" ? "bank transfer" : "cash";
    if (!window.confirm(`Confirm that you paid the driver ${formatMoney(assignment?.deliveryFee)} by ${method}?`)) return;
    let reference = "";
    if (assignment?.paymentMethod === "bank_transfer") {
      reference = window.prompt("Bank transfer reference (optional):", "") || "";
    }
    setDeliveryAssignmentSavingKey(itemId);
    try {
      const res = await authFetch(`${BACKEND_URL}/delivery-assignments/${assignment.id}/mark-paid`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reference: reference.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.assignment) {
        showToast(data.error || "Couldn't mark the driver fee paid");
        return;
      }
      setDeliveryAssignments((all) => ({ ...all, [itemId]: data.assignment }));
      showToast("Driver fee marked paid — waiting for the driver to confirm receipt");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setDeliveryAssignmentSavingKey(null);
    }
  };

  const copyDeliveryAccessValue = async (value, label) => {
    try {
      await navigator.clipboard.writeText(value);
      showToast(`${label} copied`);
    } catch {
      window.prompt(`Copy the ${label.toLowerCase()}:`, value);
    }
  };

  const updateItemCarrier = async (orderId, itemId, carrier) => {
    const ok = await patchOrderItemOnBackend(itemId, { carrier });
    if (!ok) return;
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) => (i.id === itemId ? { ...i, carrier } : i)),
            }
      )
    );
    if (carrier !== "Local Delivery Driver") {
      setDeliveryAssignments((all) => {
        if (!all[itemId]) return all;
        return { ...all, [itemId]: { ...all[itemId], status: "revoked", revokedAt: new Date().toISOString() } };
      });
      setDeliveryAssignmentSecrets((all) => {
        const next = { ...all };
        delete next[itemId];
        return next;
      });
    }
  };

  const updateItemProofOfDelivery = async (orderId, itemId, proofOfDeliveryUrl) => {
    const ok = await patchOrderItemOnBackend(itemId, { proofOfDeliveryUrl });
    if (!ok) return false;
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) => (i.id === itemId ? { ...i, proofOfDeliveryUrl } : i)),
            }
      )
    );
    showToast("Proof of delivery saved");
    return true;
  };

  // Optional receipt confirmation records that the buyer received and accepted
  // the item. The private token is already visible after successful payment. This
  // confirmation does NOT release seller funds by itself.
  const confirmReceipt = async (orderId, itemId) => {
    const accepted = window.confirm(
      "Confirm only after you have received this item, inspected it, and are fully satisfied. Continue?"
    );
    if (!accepted) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/confirm-receipt`, { method: "PATCH" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't confirm delivery — try again");
        return;
      }
      if (data.token) setDeliveryTokens((d) => ({ ...d, [itemId]: data.token }));
      await persistOrders(
        orders.map((o) =>
          o.id !== orderId
            ? o
            : {
                ...o,
                items: o.items.map((i) =>
                  i.id === itemId
                    ? { ...i, buyerConfirmedAt: Date.now(), deliveryToken: data.token || i.deliveryToken || null, deliveryTokenGeneratedAt: Date.now() }
                    : i
                ),
              }
        )
      );
      showToast("Receipt confirmed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  // Recovery/display action for a token created and revealed to the buyer
  // immediately after successful payment.
  const generateDeliveryToken = async (itemId) => {
    setGeneratingTokenKey(itemId);
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/generate-delivery-token`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't generate a code — try again");
        return;
      }
      setDeliveryTokens((d) => ({ ...d, [itemId]: data.token }));
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setGeneratingTokenKey(null);
    }
  };

  const sendDeliveryTokenToSeller = async (orderId, itemId) => {
    const accepted = window.confirm(
      "Send this token only after you have received and inspected the item. Sending it lets the seller complete delivery and release payment after uploading the delivery photo. Continue?"
    );
    if (!accepted) return;
    setSendingDeliveryTokenId(itemId);
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/send-delivery-token`, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't send the token — try again");
        return;
      }
      await persistOrders(
        orders.map((order) => order.id !== orderId ? order : {
          ...order,
          items: order.items.map((item) => item.id === itemId ? {
            ...item,
            deliveryTokenSentAt: item.deliveryTokenSentAt || Date.now(),
          } : item),
        })
      );
      showToast(data.alreadySent ? "Token was already sent to the seller" : "Token sent to seller and added to Messages");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSendingDeliveryTokenId(null);
    }
  };

  // Seller-side release action. The backend requires BOTH a valid buyer
  // delivery code and an already-uploaded proof-of-delivery picture before
  // it will confirm receipt or release held payment.
  const redeemDeliveryToken = async (orderId, itemId, token) => {
    const order = orders.find((o) => o.id === orderId);
    const item = order?.items.find((i) => i.id === itemId);
    if (!item?.proofOfDeliveryUrl) {
      showToast("Upload the delivery picture first");
      return;
    }
    setRedeemingTokenKey(itemId);
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/redeem-delivery-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "That code didn't work — try again");
        return;
      }
      await persistOrders(
        orders.map((o) =>
          o.id !== orderId
            ? o
            : {
                ...o,
                paymentStatus: data.order ? "released" : o.paymentStatus,
                items: o.items.map((i) => (i.id === itemId ? { ...i, fulfillmentStatus: data.item?.fulfillment_status || i.fulfillmentStatus, deliveryTokenRedeemedAt: data.item?.delivery_token_redeemed_at ? new Date(data.item.delivery_token_redeemed_at).getTime() : Date.now(), deliveryToken: null } : i)),
              }
        )
      );
      setRedeemTokenDrafts((d) => {
        const next = { ...d };
        delete next[itemId];
        return next;
      });
      showToast(data.order ? "Delivery confirmed — payment released!" : "Delivery confirmed");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setRedeemingTokenKey(null);
    }
  };

  const updateReturnTracking = async (orderId, itemId, trackingNumber) => {
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/return-tracking`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trackingNumber }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || "Couldn't save that tracking number — try again");
      return;
    }
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) => (i.id === itemId ? { ...i, returnTrackingNumber: trackingNumber } : i)),
            }
      )
    );
    showToast("Return tracking number saved");
  };

  const requestReturn = async (orderId, itemId, reason, note, evidenceUrls = []) => {
    if (!reason) {
      showToast("Pick a reason for the return");
      return;
    }
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/request-return`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason, note: note.trim(), evidenceUrls }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || "Couldn't submit that return — try again");
      return;
    }
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) =>
                i.id === itemId
                  ? {
                      ...i,
                      returnStatus: "requested",
                      returnReason: reason,
                      returnNote: note.trim(),
                      returnRequestedAt: Date.now(),
                      returnEvidenceUrls: evidenceUrls,
                    }
                  : i
              ),
            }
      )
    );
    showToast("Return requested");
  };

  const requestCancellation = async (orderId, itemId) => {
    const reason = window.prompt("Why do you want to cancel this item?");
    if (!reason?.trim()) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/request-cancellation`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't request cancellation");
        return;
      }
      await persistOrders(orders.map((order) => order.id !== orderId ? order : {
        ...order,
        items: order.items.map((item) => item.id === itemId ? {
          ...item,
          cancellationStatus: "requested",
          cancellationReason: reason.trim(),
          cancellationRequestedAt: Date.now(),
        } : item),
      }));
      showToast("Cancellation request sent to the seller");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const respondToCancellation = async (orderId, itemId, decision) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/cancellation-response`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't update the cancellation request");
        return;
      }
      await persistOrders(orders.map((order) => order.id !== orderId ? order : {
        ...order,
        items: order.items.map((item) => item.id === itemId ? {
          ...item,
          cancellationStatus: decision,
          cancellationRespondedAt: Date.now(),
          fulfillmentStatus: decision === "approved" ? "cancelled" : item.fulfillmentStatus,
          deliveryToken: decision === "approved" ? null : item.deliveryToken,
        } : item),
      }));
      showToast(decision === "approved" ? "Cancellation approved — refund review notified" : "Cancellation denied");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const approveReturn = async (orderId, itemId) => {
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/return-response`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: "approved" }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || "Couldn't approve that return — try again");
      return;
    }
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) =>
                i.id === itemId
                  ? {
                      ...i,
                      returnStatus: "approved",
                      fulfillmentStatus: "returned",
                      statusHistory: [...(i.statusHistory || []), { status: "returned", at: Date.now() }],
                    }
                  : i
              ),
            }
      )
    );
    showToast("Return approved");
  };

  const denyReturn = async (orderId, itemId) => {
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/return-response`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: "denied" }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || "Couldn't deny that return — try again");
      return;
    }
    await persistOrders(
      orders.map((o) =>
        o.id !== orderId
          ? o
          : {
              ...o,
              items: o.items.map((i) => (i.id === itemId ? { ...i, returnStatus: "denied" } : i)),
            }
      )
    );
    showToast("Return request denied");
  };

  const loadBankList = async () => {
    if (bankList.length > 0) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/paystack/banks`);
      if (res.ok) {
        const { banks } = await res.json();
        setBankList(banks);
      }
    } catch {
      // bank list couldn't load — the field will just be empty
    }
  };

  const toggleTwoFactor = async (enabled) => {
    setSavingTwoFactorToggle(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/profile/two-factor`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't update that — try again");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, twoFactorEnabled: data.twoFactorEnabled } : m))
      );
      showToast(data.twoFactorEnabled ? "Two-factor authentication turned on" : "Two-factor authentication turned off");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSavingTwoFactorToggle(false);
    }
  };

  // Step 1: request the code. Doesn't touch twoFactorEnabled — the account
  // only actually becomes 2FA-on once verifyEnableTwoFactorCode succeeds.
  const sendEnableTwoFactorCode = async () => {
    setSendingEnable2FACode(true);
    setEnable2FAError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/profile/two-factor/enable/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const data = await res.json();
      if (!res.ok) {
        setEnable2FAError(data.error || "Couldn't send a code — try again");
        return;
      }
      setEnable2FAStep("code");
      setEnable2FACodeInput("");
      showToast("Code sent — check your email");
    } catch {
      setEnable2FAError("Couldn't reach the server — try again");
    } finally {
      setSendingEnable2FACode(false);
    }
  };

  // Step 2: the emailed code actually flips two_factor_enabled to true.
  const verifyEnableTwoFactorCode = async () => {
    if (!enable2FACodeInput.trim()) {
      setEnable2FAError("Enter the code we emailed you");
      return;
    }
    setVerifyingEnable2FACode(true);
    setEnable2FAError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/profile/two-factor/enable/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: enable2FACodeInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setEnable2FAError(data.error || "That code didn't work");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, twoFactorEnabled: data.twoFactorEnabled } : m))
      );
      setEnable2FAStep("idle");
      setEnable2FACodeInput("");
      showToast("Two-factor authentication turned on");
    } catch {
      setEnable2FAError("Couldn't reach the server — try again");
    } finally {
      setVerifyingEnable2FACode(false);
    }
  };

  // Admin-only step 1: fetch a fresh secret + QR code to scan into an
  // authenticator app. Doesn't turn 2FA on yet — that's confirmAdminTotpSetup.
  const startAdminTotpSetup = async () => {
    setStartingAdminTotpSetup(true);
    setAdminTotpError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/totp/setup`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setAdminTotpError(data.error || "Couldn't start setup — try again");
        return;
      }
      setAdminTotpSetup(data);
      setAdminTotpCodeInput("");
    } catch {
      setAdminTotpError("Couldn't reach the server — try again");
    } finally {
      setStartingAdminTotpSetup(false);
    }
  };

  // Admin-only step 2: the code from the authenticator app confirms setup
  // and actually flips two_factor_enabled on.
  const confirmAdminTotpSetup = async () => {
    if (!adminTotpCodeInput.trim()) {
      setAdminTotpError("Enter the code from your authenticator app");
      return;
    }
    setConfirmingAdminTotpSetup(true);
    setAdminTotpError("");
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/totp/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: adminTotpCodeInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAdminTotpError(data.error || "That code didn't work");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, twoFactorEnabled: data.twoFactorEnabled } : m))
      );
      setAdminTotpSetup(null);
      setAdminTotpCodeInput("");
      showToast("Two-factor authentication turned on");
    } catch {
      setAdminTotpError("Couldn't reach the server — try again");
    } finally {
      setConfirmingAdminTotpSetup(false);
    }
  };

  const signOutOtherDevices = async () => {
    setSigningOutOtherDevices(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/profile/sign-out-other-devices`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't do that — try again");
        return;
      }
      if (data.token) await saveAuthToken(true);
      showToast("Signed out of all other devices");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSigningOutOtherDevices(false);
    }
  };

  const reportSuspiciousActivity = async () => {
    if (!suspiciousActivityMessage.trim()) {
      showToast("Describe what happened first");
      return;
    }
    setSubmittingSuspiciousReport(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/account-reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: suspiciousActivityMessage.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't submit that — try again");
        return;
      }
      setSuspiciousActivityMessage("");
      showToast("Reported — an admin will take a look");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setSubmittingSuspiciousReport(false);
    }
  };

  const changePassword = async () => {
    if (!changePasswordForm.current || !changePasswordForm.next) {
      showToast("Fill in your current and new password");
      return;
    }
    if (changePasswordForm.next.length < 8) {
      showToast("New password must be at least 8 characters");
      return;
    }
    if (changePasswordForm.next !== changePasswordForm.confirm) {
      showToast("New passwords don't match");
      return;
    }
    setChangingPassword(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/profile/change-password`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          currentPassword: changePasswordForm.current,
          newPassword: changePasswordForm.next,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't change your password — try again");
        return;
      }
      if (data.token) await saveAuthToken(true);
      setChangePasswordForm({ current: "", next: "", confirm: "" });
      showToast("Password changed — you've been signed out of other devices");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setChangingPassword(false);
    }
  };

  const saveBankDetails = async () => {
    if (!bankForm.bankCode || !bankForm.accountNumber.trim()) {
      showToast("Choose a bank and enter your account number");
      return;
    }
    if (bankResolution.status !== "verified" || !bankResolution.nameMatches) {
      showToast("Wait for Paystack to verify an account owner name that matches your identity");
      return;
    }
    if (!bankOwnerConfirmed) {
      showToast("Confirm that the displayed account owner name is yours");
      return;
    }
    setBankSaving(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/sellers/bank-details`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: currentMember.backendId,
          bankCode: bankForm.bankCode,
          accountNumber: bankForm.accountNumber.trim(),
          confirmedAccountName: bankResolution.accountName,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't verify those bank details");
        return;
      }
      if (data.confirmationRequired) {
        setPendingBankChange(true);
        setBankChangeCodeInput("");
        showToast("Check your email for a confirmation code");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, hasBankDetails: true } : m))
      );
      showToast(`Bank details saved${data.accountName ? ` for ${data.accountName}` : ""}`);
      setBankForm({ bankCode: "", accountNumber: "" });
      setBankOwnerConfirmed(false);
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setBankSaving(false);
    }
  };

  const confirmBankChange = async () => {
    if (!bankChangeCodeInput.trim()) {
      showToast("Enter the code we emailed you");
      return;
    }
    setBankSaving(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/sellers/bank-details/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: bankChangeCodeInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "That code didn't work");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, hasBankDetails: true } : m))
      );
      setPendingBankChange(false);
      setBankChangeCodeInput("");
      setBankForm({ bankCode: "", accountNumber: "" });
      setBankOwnerConfirmed(false);
      showToast(`Bank account updated${data.accountName ? ` for ${data.accountName}` : ""}`);
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setBankSaving(false);
    }
  };

  const sendAccountEmailCode = async () => {
    if (!currentMember?.email) {
      showToast("Add an email to your account first");
      return;
    }
    try {
      const res = await backendFetch(`${BACKEND_URL}/email-verify/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: currentMember.email }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't send a code — try again");
        return;
      }
      setAccountEmailCodeSent(true);
      setAccountEmailCodeInput("");
      showToast("Check your email for a code");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const confirmAccountEmailCode = async () => {
    if (!accountEmailCodeInput.trim()) {
      showToast("Enter the code we emailed you");
      return;
    }
    setVerifyingAccountEmail(true);
    try {
      const checkRes = await backendFetch(`${BACKEND_URL}/email-verify/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: currentMember.email, code: accountEmailCodeInput.trim() }),
      });
      const checkData = await checkRes.json();
      if (!checkRes.ok || !checkData.valid) {
        showToast("That code doesn't match — check and try again");
        return;
      }
      const attachRes = await authFetch(`${BACKEND_URL}/profile/verify-email`, { method: "PATCH" });
      if (!attachRes.ok) {
        showToast("Couldn't confirm that — try again");
        return;
      }
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, isEmailVerified: true } : m))
      );
      setAccountEmailCodeSent(false);
      setAccountEmailCodeInput("");
      showToast("Email verified");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setVerifyingAccountEmail(false);
    }
  };

  const sendAccountPhoneCode = async () => {
    if (!accountPhoneInput.trim()) {
      showToast("Enter a phone number");
      return;
    }
    try {
      const res = await backendFetch(`${BACKEND_URL}/phone-verify/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone: accountPhoneInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't send a code — try again");
        return;
      }
      setAccountPhoneCodeSent(true);
      setAccountPhoneCodeInput("");
      showToast("Check your phone for a code");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const confirmAccountPhoneCode = async () => {
    if (!accountPhoneCodeInput.trim()) {
      showToast("Enter the code we texted you");
      return;
    }
    setVerifyingAccountPhone(true);
    try {
      const checkRes = await backendFetch(`${BACKEND_URL}/phone-verify/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone: accountPhoneInput.trim(), code: accountPhoneCodeInput.trim() }),
      });
      const checkData = await checkRes.json();
      if (!checkRes.ok || !checkData.valid) {
        showToast("That code doesn't match — check and try again");
        return;
      }
      const attachRes = await authFetch(`${BACKEND_URL}/profile/verify-phone`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone: accountPhoneInput.trim() }),
      });
      if (!attachRes.ok) {
        showToast("Couldn't confirm that — try again");
        return;
      }
      await persistMembers(
        members.map((m) =>
          m.username === currentUser ? { ...m, phone: accountPhoneInput.trim(), isPhoneVerified: true } : m
        )
      );
      setAccountPhoneCodeSent(false);
      setAccountPhoneCodeInput("");
      setAccountPhoneInput("");
      showToast("Phone verified");
    } catch {
      showToast("Couldn't reach the server — try again");
    } finally {
      setVerifyingAccountPhone(false);
    }
  };

  const requestWithdrawal = async (amount) => {
    const amt = Math.round(Number(amount) * 100) / 100;
    if (!amt || amt <= 0) {
      showToast("Enter an amount to withdraw");
      return;
    }
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/withdrawals`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amount: amt }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || "Couldn't process that withdrawal");
      return;
    }
    const w = data.withdrawal;
    const mapped = {
      id: w.id,
      sellerUsername: w.seller_username,
      sellerId: w.seller_id,
      amount: Number(w.amount),
      status: w.status,
      failureReason: w.failure_reason,
      requestedAt: w.requested_at ? new Date(w.requested_at).getTime() : Date.now(),
      processedAt: w.processed_at ? new Date(w.processed_at).getTime() : null,
    };
    await persistWithdrawals([mapped, ...withdrawals]);
    showToast(
      mapped.status === "paid"
        ? "Withdrawal sent to your bank"
        : `Withdrawal couldn't be completed: ${mapped.failureReason || "unknown error"}`
    );
  };

  const saveCheckoutAddressIfNeeded = async () => {
    if (!saveShippingAddress) return;
    const duplicate = savedAddresses.some((a) =>
      String(a.street || "").trim().toLowerCase() === shippingForm.street.trim().toLowerCase() &&
      String(a.city || "").trim().toLowerCase() === shippingForm.city.trim().toLowerCase()
    );
    if (duplicate) return;
    try {
      const res = await authFetch(`${BACKEND_URL}/addresses`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...shippingForm, label: "Delivery address" }),
      });
      if (res.ok) {
        const saved = await res.json();
        setSavedAddresses((addresses) => [saved, ...addresses]);
      }
    } catch {
      // Saving an address is optional and must never interrupt a paid checkout.
    }
  };

  const checkout = async () => {
    if (cartItems.length === 0) return;
    if (!currentUser) {
      setCartOpen(false);
      setAuthMode("login");
      setAuthError("");
      setAuthReturnView(view);
      setView("signin");
      showToast("Log in to check out");
      return;
    }
    if (!shippingForm.fullName.trim() || !shippingForm.phone.trim() || !shippingForm.street.trim() || !shippingForm.city.trim() || !shippingForm.zip.trim() || !shippingForm.country.trim()) {
      setShippingError("Fill in the recipient name, phone, street, city, and postal code for delivery in Nigeria.");
      return;
    }
    setShippingError("");
    setCheckoutSubmitting(true);
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/checkout/initialize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          items: cartItems.map((i) => ({ listingId: i.id, qty: i.qty })),
          shippingAddress: { ...shippingForm },
          currency: cartCurrency,
          saveCard: saveCardAtCheckout,
        }),
      });
    } catch {
      setShippingError("Couldn't reach the server — check your connection and try again.");
      setCheckoutSubmitting(false);
      return;
    }
    const data = await res.json();
    if (!res.ok) {
      setShippingError(data.error || "Something went wrong starting checkout.");
      setCheckoutSubmitting(false);
      return;
    }
    if (saveShippingAddress) {
      await saveCheckoutAddressIfNeeded();
      await persistMembers(
        members.map((m) => (m.username === currentUser ? { ...m, shippingAddress: { ...shippingForm } } : m))
      );
    }
    // The cart, order, and listing status all stay exactly as they are
    // until payment actually succeeds — verifyCheckout (triggered by
    // Paystack redirecting back to /order-confirmation) is what finalizes
    // all of that, not this step.
    window.location.href = data.authorizationUrl;
  };

  // Called once Paystack redirects back to /order-confirmation?reference=...
  // Confirms the payment actually went through, then finalizes everything
  // locally that the backend already finalized on its end: adds the real
  // order, marks the purchased listings sold, and clears the cart.
  const verifyCheckout = async (reference) => {
    setCheckoutVerifying(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/checkout/verify/${reference}`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setCheckoutVerifyError(data.error || "We couldn't confirm this payment — contact support if you were charged.");
        return;
      }
      const order = backendOrderToFrontend(data.order);
      const purchasedIds = new Set(order.items.map((i) => i.listingId));
      await persistListings(listings.map((l) => (purchasedIds.has(l.id) ? { ...l, status: "sold" } : l)));
      await persistOrders([order, ...orders.filter((o) => o.id !== order.id)]);
      await persistCart([]);
      setConfirmedOrder(order);
    } catch {
      setCheckoutVerifyError("Couldn't reach the server — contact support if you were charged.");
    } finally {
      setCheckoutVerifying(false);
    }
  };

  // One-tap checkout with a card saved from an earlier purchase — no
  // redirect to Paystack needed, the charge happens directly.
  const payWithSavedCard = async (cardId) => {
    if (cartItems.length === 0) return;
    if (!shippingForm.fullName.trim() || !shippingForm.phone.trim() || !shippingForm.street.trim() || !shippingForm.city.trim() || !shippingForm.zip.trim() || !shippingForm.country.trim()) {
      setShippingError("Fill in the recipient name, phone, street, city, and postal code for delivery in Nigeria.");
      return;
    }
    setShippingError("");
    setCheckoutSubmitting(true);
    try {
      const res = await authFetch(`${BACKEND_URL}/checkout/pay-with-saved-card`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          items: cartItems.map((i) => ({ listingId: i.id, qty: i.qty })),
          shippingAddress: { ...shippingForm },
          currency: cartCurrency,
          cardId,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setShippingError(data.error || "That card couldn't be charged — try a different one.");
        return;
      }
      if (saveShippingAddress) {
        await saveCheckoutAddressIfNeeded();
        await persistMembers(
          members.map((m) => (m.username === currentUser ? { ...m, shippingAddress: { ...shippingForm } } : m))
        );
      }
      const order = backendOrderToFrontend(data.order);
      const purchasedIds = new Set(order.items.map((i) => i.listingId));
      await persistListings(listings.map((l) => (purchasedIds.has(l.id) ? { ...l, status: "sold" } : l)));
      await persistOrders([order, ...orders.filter((o) => o.id !== order.id)]);
      await persistCart([]);
      setCartOpen(false);
      setConfirmedOrder(order);
    } catch {
      setShippingError("Couldn't reach the server — check your connection and try again.");
    } finally {
      setCheckoutSubmitting(false);
    }
  };

  const setDefaultSavedCard = async (cardId) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/saved-cards/${cardId}/default`, { method: "PATCH" });
      if (!res.ok) {
        showToast("Couldn't update your saved cards");
        return;
      }
      setSavedCards((cards) => cards.map((c) => ({ ...c, is_default: c.id === cardId })));
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const deleteSavedCard = async (cardId) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/saved-cards/${cardId}`, { method: "DELETE" });
      if (!res.ok) {
        showToast("Couldn't remove that card");
        return;
      }
      setSavedCards((cards) => cards.filter((c) => c.id !== cardId));
      showToast("Card removed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const [addressDraft, setAddressDraft] = useState(null); // null | {id?, label, street, city, state, zip, country}
  const [addressSaving, setAddressSaving] = useState(false);
  const [addressError, setAddressError] = useState("");

  const startNewAddress = () => {
    setAddressDraft({ label: "", fullName: currentMember?.displayName || "", phone: currentMember?.phone || "", street: "", city: "", state: "", zip: "", country: "Nigeria", deliveryInstructions: "", preferredDeliveryTime: "", locationPhotos: [] });
    setAddressError("");
  };

  const startEditAddress = (a) => {
    setAddressDraft({
      id: a.id,
      label: a.label || "",
      fullName: a.full_name || "",
      phone: a.phone || "",
      street: a.street || "",
      city: a.city || "",
      state: a.state || "",
      zip: a.zip || "",
      country: "Nigeria",
      deliveryInstructions: a.delivery_instructions || "",
      preferredDeliveryTime: a.preferred_delivery_time || "",
      locationPhotos: a.location_photos || [],
    });
    setAddressError("");
  };

  const handleSavedAddressLocationPhotos = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = "";
    if (!addressDraft) return;
    const room = 5 - (addressDraft.locationPhotos || []).length;
    if (room <= 0) return showToast("You can add up to 5 delivery-location photos");
    try {
      const photos = [];
      for (const file of files.slice(0, room)) {
        if (!file.type.startsWith("image/") || file.size > 5 * 1024 * 1024) throw new Error();
        photos.push(await resizeImageFile(file, 1200, 0.78));
      }
      setAddressDraft((draft) => ({ ...draft, locationPhotos: [...(draft.locationPhotos || []), ...photos].slice(0, 5) }));
    } catch {
      showToast("Use image files under 5MB each");
    }
  };

  const saveAddressDraft = async () => {
    if (!addressDraft.fullName?.trim() || !addressDraft.phone?.trim() || !addressDraft.street.trim() || !addressDraft.city.trim() || !addressDraft.country.trim()) {
      setAddressError("Recipient name, phone, street, and city are required for a Nigerian delivery address.");
      return;
    }
    setAddressSaving(true);
    setAddressError("");
    try {
      const isEdit = !!addressDraft.id;
      const res = await authFetch(`${BACKEND_URL}/addresses${isEdit ? `/${addressDraft.id}` : ""}`, {
        method: isEdit ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addressDraft),
      });
      const data = await res.json();
      if (!res.ok) {
        setAddressError(data.error || "Couldn't save that address");
        return;
      }
      if (isEdit) {
        setSavedAddresses((addrs) => addrs.map((a) => (a.id === data.id ? data : a)));
      } else {
        setSavedAddresses((addrs) => [data, ...addrs]);
      }
      setAddressDraft(null);
      showToast(isEdit ? "Address updated" : "Address saved");
    } catch {
      setAddressError("Couldn't reach the server — try again");
    } finally {
      setAddressSaving(false);
    }
  };

  const setDefaultSavedAddress = async (id) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/addresses/${id}/default`, { method: "PATCH" });
      if (!res.ok) {
        showToast("Couldn't update your addresses");
        return;
      }
      setSavedAddresses((addrs) => addrs.map((a) => ({ ...a, is_default: a.id === id })));
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const deleteSavedAddress = async (id) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/addresses/${id}`, { method: "DELETE" });
      if (!res.ok) {
        showToast("Couldn't remove that address");
        return;
      }
      setSavedAddresses((addrs) => addrs.filter((a) => a.id !== id));
      showToast("Address removed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const resetForm = () => {
    setForm({
      title: "",
      description: "",
      price: "",
      category: "Handmade",
      condition: "New",
      emoji: "📦",
      fitMake: "",
      fitModel: "",
      fitYear: "",
      images: [],
      listingType: "fixed",
      auctionDurationDays: "3",
      currency: "NGN",
      shippingFee: "0.00",
      quantity: "",
      sku: "",
      brand: "",
      state: "",
      shippingMethods: [],
      returnPolicy: "",
      vin: "",
    });
    setEditingId(null);
    setPreviewOpen(false);
  };

  const handlePhotoSelect = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = "";
    if (files.length === 0) return;
    const room = MAX_LISTING_PHOTOS - form.images.length;
    if (room <= 0) {
      showToast(`You can add up to ${MAX_LISTING_PHOTOS} photos`);
      return;
    }
    const toProcess = files.slice(0, room);
    if (files.length > room) showToast(`Only added the first ${room === 1 ? "photo" : `${room} photos`} — you're at the ${MAX_LISTING_PHOTOS}-photo limit`);

    setUploading(true);
    setPhotoUploadProgress(toProcess.map((f) => ({ name: f.name, status: "uploading", message: "" })));

    const setStatus = (index, status, message = "") => {
      setPhotoUploadProgress((prev) => {
        const next = [...prev];
        next[index] = { ...next[index], status, message };
        return next;
      });
    };

    const uploaded = [];
    for (let i = 0; i < toProcess.length; i++) {
      const file = toProcess[i];
      try {
        if (file.size > MAX_LISTING_PHOTO_BYTES) {
          setStatus(i, "error", "Over 12 MB");
          continue;
        }
        // Browsers can't natively decode HEIC/HEIF (the format iPhones use
        // by default), so it has to be converted to JPEG first. Some
        // browsers/OSes report the wrong MIME type (or none at all, or a
        // generic one) for these files, so the filename extension is
        // checked too — and checked before the type-rejection below, so a
        // real HEIC file with a mislabeled type doesn't get bounced before
        // it's even recognized as HEIC.
        const looksLikeHeic = file.type === "image/heic" || file.type === "image/heif" || /\.hei[cf]$/i.test(file.name);

        if (!looksLikeHeic && file.type && !ACCEPTED_PHOTO_TYPES.includes(file.type)) {
          setStatus(i, "error", "Unsupported file type");
          continue;
        }

        // The conversion library itself is only downloaded when someone
        // actually uploads a HEIC file — not part of everyone's page load.
        let fileToProcess = file;
        if (looksLikeHeic) {
          setStatus(i, "uploading", "Converting HEIC photo…");
          try {
            const heic2any = (await import("heic2any")).default;
            const converted = await heic2any({ blob: file, toType: "image/jpeg", quality: 0.9 });
            const convertedBlob = Array.isArray(converted) ? converted[0] : converted;
            fileToProcess = new File([convertedBlob], file.name.replace(/\.hei[cf]$/i, ".jpg"), { type: "image/jpeg" });
          } catch {
            setStatus(i, "error", "Couldn't convert this HEIC photo — try exporting it as JPEG first");
            continue;
          }
        }

        let resized;
        try {
          resized = await resizeListingPhoto(fileToProcess);
        } catch {
          setStatus(i, "error", "Couldn't read this file — it may be corrupted");
          continue;
        }

        if (resized.originalWidth < MIN_LISTING_PHOTO_DIM || resized.originalHeight < MIN_LISTING_PHOTO_DIM) {
          setStatus(i, "error", `Too small — needs to be at least ${MIN_LISTING_PHOTO_DIM}×${MIN_LISTING_PHOTO_DIM}px`);
          continue;
        }
        const belowRecommended =
          resized.originalWidth < RECOMMENDED_LISTING_PHOTO_DIM || resized.originalHeight < RECOMMENDED_LISTING_PHOTO_DIM;
        const qualityWarnings = [];
        if (resized.isBlurry) qualityWarnings.push("looks blurry");
        if (resized.isTooDark) qualityWarnings.push("looks too dark");
        if (resized.isTooBright) qualityWarnings.push("looks overexposed");
        if (belowRecommended) qualityWarnings.push(`below the recommended ${RECOMMENDED_LISTING_PHOTO_DIM}×${RECOMMENDED_LISTING_PHOTO_DIM}px`);

        const res = await authFetch(`${BACKEND_URL}/uploads/image`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ dataUrl: resized.dataUrl, folder: "listings/products" }),
        });
        const data = await res.json();
        if (!res.ok) {
          setStatus(i, "error", data.error || "Upload failed");
          continue;
        }
        uploaded.push(data.url);
        setStatus(
          i,
          "done",
          qualityWarnings.length ? `Added, but this photo ${qualityWarnings.join(" and ")} — consider replacing it` : "Added"
        );
      } catch {
        setStatus(i, "error", "Couldn't reach the server");
      }
    }

    if (uploaded.length) {
      setForm((f) => ({ ...f, images: [...f.images, ...uploaded].slice(0, MAX_LISTING_PHOTOS) }));
    }
    setUploading(false);
    // Leave the progress list showing briefly so the seller can see what
    // happened to each file (especially any that failed), then clear it.
    setTimeout(() => setPhotoUploadProgress([]), 4000);
  };

  // Drag-to-reorder for listing photos. The first photo is always the
  // main/cover image, so reordering is also how a seller picks a new one —
  // drag any other photo to the front.
  const [draggedPhotoIndex, setDraggedPhotoIndex] = useState(null);
  const reorderListingPhotos = (fromIndex, toIndex) => {
    setForm((f) => {
      const next = [...f.images];
      const [moved] = next.splice(fromIndex, 1);
      next.splice(toIndex, 0, moved);
      return { ...f, images: next };
    });
  };
  const makeListingPhotoMain = (index) => {
    if (index === 0) return;
    reorderListingPhotos(index, 0);
  };

  const removePhoto = (idx) => {
    setForm((f) => ({ ...f, images: f.images.filter((_, i) => i !== idx) }));
  };

  const handleLicensePhotoSelect = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = "";
    if (files.length === 0) return;
    const room = 5 - authForm.licensePhotos.length;
    if (room <= 0) {
      showToast("You can add up to 5 license photos");
      return;
    }
    setUploadingLicense(true);
    try {
      const toProcess = files.slice(0, room);
      const results = await Promise.all(toProcess.map((f) => resizeImageFile(f)));
      setAuthForm((f) => ({ ...f, licensePhotos: [...f.licensePhotos, ...results].slice(0, 5) }));
      if (files.length > room) showToast("Only added the first 5 photos");
    } catch {
      showToast("Couldn't process one of those photos");
    } finally {
      setUploadingLicense(false);
    }
  };

  const removeLicensePhoto = (idx) => {
    setAuthForm((f) => ({ ...f, licensePhotos: f.licensePhotos.filter((_, i) => i !== idx) }));
  };

  const handleBankStatementSelect = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      showToast("That file is too large — please upload something under 5MB");
      return;
    }
    setUploadingBankStatement(true);
    try {
      const dataUrl = file.type.startsWith("image/")
        ? await resizeImageFile(file, 1400, 0.85)
        : await readFileAsDataURL(file);
      setBankStatementDraft(dataUrl);
      showToast("Bank statement attached");
    } catch {
      showToast("Couldn't read that file — try a different one");
    } finally {
      setUploadingBankStatement(false);
    }
  };

  const handleVerifiedSellerIdSelect = async (e, side) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/") || file.size > 5 * 1024 * 1024) {
      showToast("Choose a clear ID image under 5MB");
      return;
    }
    setUploadingVerifiedSellerId(true);
    try {
      const dataUrl = await resizeImageFile(file, 1400, 0.86);
      setVerifiedSellerIdImages((current) => ({ ...current, [side]: dataUrl }));
      showToast(`${side === "front" ? "Front" : "Back"} of identification attached`);
    } catch {
      showToast("Couldn't process that identification image");
    } finally {
      setUploadingVerifiedSellerId(false);
    }
  };

  const saveLiveDeliveryPhoto = async (dataUrl) => {
    if (!deliveryPhotoTarget || uploadingPodKey) return;
    const { orderId, itemId } = deliveryPhotoTarget;
    setUploadingPodKey(`${orderId}-${itemId}`);
    try {
      const saved = await updateItemProofOfDelivery(orderId, itemId, dataUrl);
      if (saved) setDeliveryPhotoTarget(null);
    } catch {
      showToast("Couldn't save the delivery photo — try again");
    } finally { setUploadingPodKey(null); }
  };

  const runSelfDeliveryStep = async (orderId, itemId, action, extra = {}) => {
    const key = `${orderId}-${itemId}-${action}`;
    setSelfDeliveryActionKey(key);
    try {
      const res = await authFetch(`${BACKEND_URL}/order-items/${itemId}/self-delivery`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          deliveryPersonSelfieUrl: action === "selfie" ? extra.deliveryPersonSelfieUrl || deliverySelfieDrafts[itemId] || "" : undefined,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.item) {
        showToast(data.error || "Couldn't update Self delivery — try again");
        return false;
      }
      const row = data.item;
      setOrders((all) => all.map((order) => order.id !== orderId ? order : {
        ...order,
        items: order.items.map((item) => item.id !== itemId ? item : {
          ...item,
          carrier: row.carrier || item.carrier,
          fulfillmentStatus: row.fulfillment_status || item.fulfillmentStatus,
          selfDeliveryStatus: row.self_delivery_status || null,
          deliveryPersonSelfieUrl: row.delivery_person_selfie_url || "",
          selfDeliveryStartedAt: row.self_delivery_started_at ? new Date(row.self_delivery_started_at).getTime() : item.selfDeliveryStartedAt,
          selfDeliveryOnMyWayAt: row.self_delivery_on_my_way_at ? new Date(row.self_delivery_on_my_way_at).getTime() : item.selfDeliveryOnMyWayAt,
          selfDeliveryArrivedAt: row.self_delivery_arrived_at ? new Date(row.self_delivery_arrived_at).getTime() : item.selfDeliveryArrivedAt,
          selfDeliveryDeliveredAt: row.self_delivery_delivered_at ? new Date(row.self_delivery_delivered_at).getTime() : item.selfDeliveryDeliveredAt,
          liveLocationEnabled: !!row.live_location_enabled,
        }),
      }));
      if (action === "selfie") {
        setDeliverySelfieDrafts((drafts) => {
          const next = { ...drafts };
          delete next[itemId];
          return next;
        });
      }
      showToast({ start: "Self delivery started", on_my_way: "Marked On my way", selfie: "Delivery-person selfie uploaded", arrived: "Marked I’m here", delivered: "Delivery completed" }[action]);
      return true;
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    } finally {
      setSelfDeliveryActionKey(null);
    }
  };

  const closeDeliverySelfieCamera = () => {
    if (deliverySelfieStreamRef.current) {
      deliverySelfieStreamRef.current.getTracks().forEach((track) => track.stop());
      deliverySelfieStreamRef.current = null;
    }
    if (deliverySelfieVideoRef.current) deliverySelfieVideoRef.current.srcObject = null;
    setDeliverySelfieCameraReady(false);
    setDeliverySelfieCameraTarget(null);
  };

  useEffect(() => {
    if (!deliverySelfieCameraTarget) return undefined;
    let cancelled = false;
    const startCamera = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 1280 } },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach((track) => track.stop());
          return;
        }
        deliverySelfieStreamRef.current = stream;
        if (deliverySelfieVideoRef.current) {
          deliverySelfieVideoRef.current.srcObject = stream;
          await deliverySelfieVideoRef.current.play();
          setDeliverySelfieCameraReady(true);
        }
      } catch {
        showToast("Camera access is required for the live delivery-person selfie");
        setDeliverySelfieCameraTarget(null);
      }
    };
    startCamera();
    return () => {
      cancelled = true;
      if (deliverySelfieStreamRef.current) {
        deliverySelfieStreamRef.current.getTracks().forEach((track) => track.stop());
        deliverySelfieStreamRef.current = null;
      }
    };
  }, [deliverySelfieCameraTarget]);

  const captureLiveDeliverySelfie = async () => {
    const target = deliverySelfieCameraTarget;
    const video = deliverySelfieVideoRef.current;
    if (!target || !video || !deliverySelfieCameraReady || !video.videoWidth) {
      showToast("Wait for the live camera to become ready");
      return;
    }
    const key = `${target.orderId}-${target.itemId}`;
    setUploadingDeliverySelfieKey(key);
    try {
      const size = Math.min(video.videoWidth, video.videoHeight);
      const canvas = document.createElement("canvas");
      canvas.width = 960;
      canvas.height = 960;
      const context = canvas.getContext("2d");
      const sourceX = Math.max(0, (video.videoWidth - size) / 2);
      const sourceY = Math.max(0, (video.videoHeight - size) / 2);
      context.drawImage(video, sourceX, sourceY, size, size, 0, 0, 960, 960);
      const dataUrl = canvas.toDataURL("image/jpeg", 0.84);
      const res = await authFetch(`${BACKEND_URL}/uploads/image`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataUrl, folder: "self-delivery/live-selfies" }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.url) throw new Error(data.error || "Couldn't upload the live selfie");
      const saved = await runSelfDeliveryStep(target.orderId, target.itemId, "selfie", {
        deliveryPersonSelfieUrl: data.url,
      });
      if (saved) closeDeliverySelfieCamera();
    } catch (err) {
      showToast(err.message || "Couldn't save the live selfie — try again");
    } finally {
      setUploadingDeliverySelfieKey(null);
    }
  };

  const handleDeliveryLocationPhotos = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = "";
    const room = 5 - (shippingForm.locationPhotos || []).length;
    if (!files.length || room <= 0) {
      if (room <= 0) showToast("You can add up to 5 delivery-location photos");
      return;
    }
    setUploadingLocationPhotos(true);
    try {
      const accepted = files.slice(0, room);
      if (accepted.some((file) => !file.type.startsWith("image/") || file.size > 5 * 1024 * 1024)) {
        showToast("Use image files under 5MB each");
        return;
      }
      const photos = [];
      for (const file of accepted) photos.push(await resizeImageFile(file, 1200, 0.78));
      setShippingForm((form) => ({
        ...form,
        locationPhotos: [...(form.locationPhotos || []), ...photos].slice(0, 5),
      }));
      if (files.length > room) showToast("Only the first 5 delivery-location photos were added");
    } catch {
      showToast("Couldn't process one of those location photos");
    } finally {
      setUploadingLocationPhotos(false);
    }
  };

  const handleReturnEvidenceSelect = async (e, draftKey) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      showToast("That photo is too large — please upload something under 5MB");
      return;
    }
    setUploadingReturnEvidenceKey(draftKey);
    try {
      const dataUrl = await resizeImageFile(file, 1400, 0.85);
      setReturnDrafts((d) => ({
        ...d,
        [draftKey]: { ...d[draftKey], evidenceUrls: [...(d[draftKey]?.evidenceUrls || []), dataUrl] },
      }));
    } catch {
      showToast("Couldn't read that photo — try a different one");
    } finally {
      setUploadingReturnEvidenceKey(null);
    }
  };

  const handleBannerImageSelect = async (e) => {
    const file = (e.target.files || [])[0];
    e.target.value = "";
    if (!file) return;
    setBannerImageUploading(true);
    try {
      const resized = await resizeImageFile(file, 1400, 0.8);
      setBannerForm((f) => ({ ...f, imageUrl: resized }));
    } catch {
      showToast("Couldn't process that image");
    } finally {
      setBannerImageUploading(false);
    }
  };


  const handleHomepageAdImageSelect = async (e, slot) => {
    const file = (e.target.files || [])[0];
    e.target.value = "";
    if (!file) return;
    setHomepageAdUploading(slot);
    try {
      const optimized = await resizeHomepageHero(file, "desktop");
      const res = await authFetch(`${BACKEND_URL}/uploads/image`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataUrl: optimized.dataUrl, folder: "homepage-ads" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Upload failed");
      setHomepageAds((ads) => ads.map((ad) => ad.slot === slot ? { ...ad, imageUrl: data.url, mediaType: "image" } : ad));
      const sizeKb = Math.max(1, Math.round(optimized.sizeBytes / 1024));
      showToast(`Slide ${slot} desktop image: ${optimized.width}×${optimized.height} WebP (${sizeKb} KB) — save the slide when ready`);
    } catch (err) {
      showToast(err.message || "Couldn't upload that ad image");
    } finally {
      setHomepageAdUploading(null);
    }
  };

  const handleHomepageAdVideoSelect = async (e, slot) => {
    const file = (e.target.files || [])[0];
    e.target.value = "";
    if (!file || slot !== 1) return;
    if (!["video/mp4", "video/webm"].includes(file.type)) {
      showToast("Use an MP4 or WebM video");
      return;
    }
    if (file.size > 40 * 1024 * 1024) {
      showToast("Video is too large — maximum size is 40 MB");
      return;
    }
    setHomepageAdUploading(slot);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/homepage-ads/upload-video`, {
        method: "POST",
        headers: { "Content-Type": file.type },
        body: file,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Video upload failed");
      setHomepageAds((ads) => ads.map((ad) => ad.slot === slot ? {
        ...ad,
        imageUrl: data.url,
        mediaType: "video",
      } : ad));
      showToast("Ad 1 video uploaded — click Save ad to publish it");
    } catch (err) {
      showToast(err.message || "Couldn't upload that ad video");
    } finally {
      setHomepageAdUploading(null);
    }
  };

  const handleHomepageAdMobileImageSelect = async (e, slot) => {
    const file = (e.target.files || [])[0];
    e.target.value = "";
    if (!file) return;
    setHomepageAdUploading(slot);
    try {
      const optimized = await resizeHomepageHero(file, "mobile");
      const res = await authFetch(`${BACKEND_URL}/uploads/image`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataUrl: optimized.dataUrl, folder: "homepage-ads/mobile" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Mobile image upload failed");
      setHomepageAds((ads) => ads.map((ad) => ad.slot === slot ? { ...ad, posterUrl: data.url } : ad));
      const sizeKb = Math.max(1, Math.round(optimized.sizeBytes / 1024));
      showToast(`Slide ${slot} mobile image: ${optimized.width}×${optimized.height} WebP (${sizeKb} KB) — save the slide when ready`);
    } catch (err) {
      showToast(err.message || "Couldn't upload that mobile image");
    } finally {
      setHomepageAdUploading(null);
    }
  };

  const saveHomepageAd = async (slot) => {
    const ad = homepageAds.find((item) => item.slot === slot);
    if (!ad) return;
    setHomepageAdSaving(slot);
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/homepage-ads/${slot}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          imageUrl: ad.imageUrl || "",
          mediaType: "image",
          posterUrl: ad.posterUrl || "",
          linkUrl: ad.linkUrl || "",
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Couldn't save ad");
      setHomepageAds((ads) => ads.map((item) => item.slot === slot ? {
        slot,
        imageUrl: data.ad?.image_url || "",
        mediaType: "image",
        posterUrl: data.ad?.poster_url || "",
        linkUrl: data.ad?.link_url || "",
      } : item));
      showToast(`Homepage ad ${slot} saved`);
    } catch (err) {
      showToast(err.message || "Couldn't save homepage ad");
    } finally {
      setHomepageAdSaving(null);
    }
  };

  const handleAuthImageSelect = async (e) => {
    const file = (e.target.files || [])[0];
    e.target.value = "";
    if (!file) return;
    setAuthImageUploading(true);
    try {
      const resized = await resizeImageFile(file, 1400, 0.8);
      await persistSettings({ ...settings, authImage: resized });
    } catch {
      showToast("Couldn't process that image");
    } finally {
      setAuthImageUploading(false);
    }
  };

  const removeAuthImage = async () => {
    await persistSettings({ ...settings, authImage: "" });
  };

  const handleSubmit = async (mode = "publish") => {
    if (!currentUser) {
      setAuthMode("register");
      setAuthReturnView(view);
      setView("signup");
      showToast("Register or log in to publish a listing");
      return;
    }
    if (!hasSellerListingAccess) {
      showToast("Complete automatic casual-seller verification before publishing");
      setCasualVerificationOpen(true);
      return;
    }
    if (needsIdVerification) {
      showToast("Complete seller verification before publishing");
      setIdVerifyOpen(true);
      return;
    }
    const isDraft = mode === "draft";
    if (!form.title.trim()) {
      showToast("Give it a title");
      return;
    }
    if (!isDraft && !form.price) {
      showToast("Give it a price before publishing");
      return;
    }
    if (!isDraft && !form.subcategory) {
      showToast("Choose a subcategory before publishing");
      return;
    }
    if (!isDraft && form.images.length < MIN_LISTING_PHOTOS) {
      showToast(`Add at least ${MIN_LISTING_PHOTOS} photos before publishing`);
      return;
    }
    if (form.listingType === "auction" && false) {
      showToast("Auctions are not available for this listing");
      return;
    }
    if (editingId) {
      const existingListing = listings.find((l) => l.id === editingId);
      if (existingListing?.listingType === "auction" && (existingListing.bidHistory || []).length > 0) {
        showToast("This auction already has bids and can't be edited");
        return;
      }
      // Publishing a draft (or re-saving as a draft) re-runs the same
      // approval logic a brand-new listing would get, since a draft has
      // never been through it yet.
      let statusPatch = {};
      if (isDraft) {
        statusPatch = { status: "draft" };
      } else if (existingListing?.status === "draft" || existingListing?.status === "rejected") {
        // Once a seller is approved, everything they list — including
        // auctions — goes live immediately without a separate review queue.
        const autoApproved = hasSellerListingAccess;
        statusPatch = { status: autoApproved ? "active" : "pending" };
      }
      const patch = {
        ...form,
        price: form.price ? Number(form.price) : 0,
        shippingFee: Number(form.shippingFee) || 0,
        ...statusPatch,
      };
      if (typeof existingListing?.id === "number") {
        try {
          const res = await authFetch(`${BACKEND_URL}/listings/${existingListing.id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(patch),
          });
          if (!res.ok) {
            let message = "Couldn't save changes — try again";
            try { const data = await res.json(); if (data?.error) message = data.error; } catch {}
            showToast(message);
            return;
          }
          const { listing } = await res.json();
          await persistListings(
            listings.map((l) => (l.id === editingId ? backendListingToFrontend(listing, l) : l))
          );
        } catch {
          showToast("Couldn't reach the server — try again");
          return;
        }
      } else {
        await persistListings(listings.map((l) => (l.id === editingId ? { ...l, ...patch } : l)));
      }
      showToast(isDraft ? "Draft saved" : "Listing updated");
    } else {
      const isAuction = form.listingType === "auction";
      // Once a seller is approved, everything they list — including
      // auctions — goes live immediately without a separate review queue.
      const autoApproved = hasSellerListingAccess;
      const status = isDraft ? "draft" : autoApproved ? "active" : "pending";
      const auctionEndTime = isAuction
        ? Date.now() + Number(form.auctionDurationDays) * 24 * 60 * 60 * 1000
        : null;
      let res;
      try {
        res = await authFetch(`${BACKEND_URL}/listings`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ownerId: currentMember.backendId,
            title: form.title,
            description: form.description,
            price: form.price ? Number(form.price) : 0,
            category: form.category,
            subcategory: form.subcategory,
            condition: form.condition,
            shippingFee: Number(form.shippingFee) || 0,
            emoji: form.emoji,
            fitMake: form.fitMake,
            fitModel: form.fitModel,
            fitYear: form.fitYear,
            images: form.images,
            listingType: form.listingType,
            currency: form.currency,
            status,
            auctionEndTime,
            quantity: form.quantity,
            sku: form.sku,
            brand: form.brand,
            state: form.state,
            shippingMethods: form.shippingMethods,
            returnPolicy: form.returnPolicy,
            vin: form.vin,
          }),
        });
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
      if (!res.ok) {
        let message = isDraft ? "Couldn't save that draft — try again" : "Couldn't publish that listing — try again";
        try {
          const data = await res.json();
          if (data?.error) message = data.error;
        } catch {
          // response wasn't JSON — fall back to the generic message above
        }
        showToast(message);
        return;
      }
      const { listing } = await res.json();
      const newListing = backendListingToFrontend(listing, {
        sellerName: currentMember.displayName,
        ownerUsername: currentUser,
      });
      await persistListings([newListing, ...listings]);
      showToast(isDraft ? "Draft saved" : autoApproved ? "Listing is live" : "Listing submitted — pending admin approval");
    }
    resetForm();
    setView(adminEditContext ? "admin" : "dashboard");
    setAdminEditContext(false);
  };

  const startEdit = (listing, fromAdmin = false) => {
    setForm({
      title: listing.title,
      description: listing.description,
      price: String(listing.price),
      category: listing.category,
      subcategory: listing.subcategory || "",
      condition: listing.condition || "New",
      emoji: listing.emoji,
      fitMake: listing.fitMake || "",
      fitModel: listing.fitModel || "",
      fitYear: listing.fitYear || "",
      images: listing.images || [],
      listingType: listing.listingType || "fixed",
      auctionDurationDays: "3",
      currency: listing.currency || "NGN",
      shippingFee: listing.shippingFee != null ? String(listing.shippingFee) : "0.00",
      quantity: listing.quantity != null ? String(listing.quantity) : "",
      sku: listing.sku || "",
      brand: listing.brand || "",
      state: listing.state || "",
      shippingMethods: listing.shippingMethods || [],
      returnPolicy: listing.returnPolicy || "",
      vin: listing.vin || "",
    });
    setEditingId(listing.id);
    setAdminEditContext(fromAdmin);
    setPreviewOpen(false);
    setView("sell");
  };

  const deleteListingOnBackend = async (id) => {
    if (typeof id !== "number") return true;
    try {
      const res = await authFetch(`${BACKEND_URL}/listings/${id}`, { method: "DELETE" });
      if (!res.ok) {
        showToast("Couldn't remove that listing — try again");
        return false;
      }
      return true;
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    }
  };

  const deleteListing = async (id) => {
    if (!(await deleteListingOnBackend(id))) return;
    await persistListings(listings.filter((l) => l.id !== id));
    showToast("Listing removed");
    setSelected(null);
  };

  const pauseListing = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "paused" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "paused" } : l)));
    showToast("Listing paused — hidden from Browse until you resume it");
  };

  const resumeListing = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "active" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "active" } : l)));
    showToast("Listing is live again");
  };

  const markListingSoldOut = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "sold" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "sold" } : l)));
    showToast("Marked out of stock");
  };

  const markListingInStock = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "active" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "active" } : l)));
    showToast("Marked back in stock");
  };

  // Prefills the create form from an existing listing (minus id, bid
  // history, and auction end time) so the seller can tweak and publish it
  // as a brand-new listing rather than starting from scratch.
  const duplicateListing = (l) => {
    setForm({
      title: `${l.title} (copy)`,
      description: l.description || "",
      price: l.price != null ? String(l.price) : "",
      category: l.category,
      condition: l.condition || "New",
      emoji: l.emoji || "📦",
      fitMake: l.fitMake || "",
      fitModel: l.fitModel || "",
      fitYear: l.fitYear || "",
      images: l.images || [],
      listingType: "fixed",
      auctionDurationDays: "3",
      currency: l.currency || "NGN",
      shippingFee: l.shippingFee != null ? String(l.shippingFee) : "0.00",
      quantity: l.quantity != null ? String(l.quantity) : "",
      sku: l.sku || "",
      brand: l.brand || "",
      state: l.state || "",
      shippingMethods: l.shippingMethods || [],
      returnPolicy: l.returnPolicy || "",
      vin: l.vin || "",
    });
    setEditingId(null);
    setAdminEditContext(false);
    setPreviewOpen(false);
    setView("sell");
    showToast("Duplicated — review and publish when ready");
  };

  // Quick inline edit for just price/quantity from the Manage Listings list,
  // without opening the full edit form.
  const quickUpdateListing = async (id, { price, quantity }) => {
    const patch = {};
    if (price !== undefined) patch.price = Number(price);
    if (quantity !== undefined) patch.quantity = quantity === "" ? null : Number(quantity);
    if (!(await patchListingOnBackend(id, patch))) return;
    await persistListings(
      listings.map((l) =>
        l.id === id
          ? {
              ...l,
              ...(price !== undefined ? { price: Number(price) } : {}),
              ...(quantity !== undefined ? { quantity: quantity === "" ? "" : Number(quantity) } : {}),
            }
          : l
      )
    );
    showToast("Listing updated");
  };

  const adminRemoveListing = async (id) => {
    if (!(await deleteListingOnBackend(id))) return;
    await persistListings(listings.filter((l) => l.id !== id));
    showToast("Listing removed by admin");
  };

  const adminApproveListing = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "active" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "active" } : l)));
    showToast("Listing approved");
  };

  const adminRejectListing = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "rejected" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "rejected" } : l)));
    showToast("Listing rejected");
  };

  const adminTakeDownListing = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "removed" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "removed" } : l)));
    showToast("Listing taken down");
  };

  // Hides or unhides one specific photo on a listing — the listing itself
  // and its other photos are untouched. Hidden photos stay in allImages
  // (nothing is deleted) but drop out of the buyer-facing images array.
  const adminToggleImageVisibility = async (listingId, url, hidden, reason = "") => {
    try {
      const res = await authFetch(`${BACKEND_URL}/listings/${listingId}/image-visibility`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, hidden, reason }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't update that photo");
        return;
      }
      const updated = backendListingToFrontend(data.listing, listings.find((l) => l.id === listingId));
      await persistListings(listings.map((l) => (l.id === listingId ? updated : l)));
      showToast(hidden ? "Photo hidden from buyers" : "Photo restored");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const dismissImageFlag = async (listingId, url) => {
    try {
      const res = await authFetch(`${BACKEND_URL}/listings/${listingId}/dismiss-flag`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || "Couldn't dismiss that flag");
        return;
      }
      const updated = backendListingToFrontend(data.listing, listings.find((l) => l.id === listingId));
      await persistListings(listings.map((l) => (l.id === listingId ? updated : l)));
      showToast("Flag dismissed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminRestoreListing = async (id) => {
    if (!(await patchListingOnBackend(id, { status: "active" }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, status: "active" } : l)));
    showToast("Listing restored");
  };

  const adminToggleFeature = async (id) => {
    const target = listings.find((l) => l.id === id);
    const nextFeatured = !target?.isFeatured;
    if (!(await patchListingOnBackend(id, { isFeatured: nextFeatured }))) return;
    await persistListings(listings.map((l) => (l.id === id ? { ...l, isFeatured: nextFeatured } : l)));
    showToast(nextFeatured ? "Listing featured" : "Listing unfeatured");
  };

  const adminRemoveMember = async (username) => {
    if (username === currentUser) {
      showToast("You can't remove your own admin account");
      return;
    }
    const target = members.find((m) => m.username === username);
    if (target?.backendId) {
      try {
        if (target.isPreview) {
          if (!window.confirm(`Delete preview account @${username} and all of its isolated test data? This cannot affect real accounts or transactions.`)) {
            return;
          }
          const res = await authFetch(`${BACKEND_URL}/admin/preview-users/${target.backendId}`, { method: "DELETE" });
          const body = await res.json().catch(() => ({}));
          if (!res.ok) {
            showToast(body.error || "Couldn't delete that preview account");
            return;
          }
          await persistMembers(members.filter((m) => m.username !== username));
          await persistListings(listings.filter((l) => l.ownerUsername !== username));
          showToast("Preview account and isolated test data deleted");
          return;
        }
        await authFetch(`${BACKEND_URL}/listings/by-owner/${target.backendId}`, { method: "DELETE" });
        const res = await authFetch(`${BACKEND_URL}/users/${target.backendId}`, { method: "DELETE" });
        if (!res.ok) {
          let body = {};
          try {
            body = await res.json();
          } catch {}
          if (body.code === "HAS_HISTORY") {
            // This member has order/payout history, so we can't hard-delete
            // them without destroying records other users depend on.
            // Suspend instead — blocks their access, keeps history intact.
            await adminToggleSuspend(username);
            showToast("Member has order or payout history, so they were suspended instead of deleted");
          } else {
            showToast("Couldn't remove member — try again");
          }
          return;
        }
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
    }
    await persistMembers(members.filter((m) => m.username !== username));
    await persistListings(listings.filter((l) => l.ownerUsername !== username));
    showToast("Member removed");
  };

  const adminSetPreviewPhoneVerification = async (username, isVerified) => {
    const target = members.find((m) => m.username === username);
    if (!target?.backendId || !target.isPreview) {
      showToast("Only preview accounts can use admin test-phone verification");
      return;
    }
    try {
      const res = await authFetch(`${BACKEND_URL}/admin/preview-users/${target.backendId}/phone-verification`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isVerified }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || "Couldn't update the preview phone verification");
        return;
      }
      const updated = backendUserToMember(data.user, target);
      await persistMembers(members.map((m) => (m.username === username ? updated : m)));
      showToast(isVerified ? "Preview phone marked verified" : "Preview phone verification removed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminSetRole = async (username, role, reason = "") => {
    const target = members.find((m) => m.username === username);
    if (target?.backendId) {
      try {
        const res = await authFetch(`${BACKEND_URL}/users/${target.backendId}/admin-role`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role, reason }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showToast(data.error || "Couldn't update that role — try again");
          return false;
        }
      } catch {
        showToast("Couldn't reach the server — try again");
        return false;
      }
    }
    await persistMembers(
      members.map((m) => (m.username === username ? { ...m, isAdmin: role !== null, adminRole: role } : m))
    );
    showToast(role ? `Role set to ${ADMIN_ROLE_LABELS[role] || role}` : "Admin access revoked");
    return true;
  };

  const adminToggleSuspend = async (username) => {
    if (username === currentUser) {
      showToast("You can't suspend your own account");
      return;
    }
    const target = members.find((m) => m.username === username);
    const nextSuspended = !target?.isSuspended;
    if (target?.backendId) {
      try {
        const res = await authFetch(`${BACKEND_URL}/users/${target.backendId}/suspend`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ isSuspended: nextSuspended }),
        });
        if (!res.ok) {
          showToast("Couldn't update member — try again");
          return;
        }
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
    }
    await persistMembers(
      members.map((m) => (m.username === username ? { ...m, isSuspended: nextSuspended } : m))
    );
    showToast(nextSuspended ? "Member suspended" : "Member unsuspended");
  };

  const adminApproveMember = async (username) => {
    const target = members.find((m) => m.username === username);
    if (target?.backendId) {
      try {
        const res = await authFetch(`${BACKEND_URL}/users/${target.backendId}/approve`, { method: "PATCH" });
        if (!res.ok) {
          let message = "Couldn't approve member — try again";
          try { const data = await res.json(); if (data?.error) message = data.error; } catch {}
          showToast(message);
          return;
        }
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
    }
    await persistMembers(
      members.map((m) =>
        m.username === username
          ? { ...m, isApproved: true, verificationStatus: "approved", rejectionReason: "" }
          : m
      )
    );
    fetchVerifiedSellerApplications();
    showToast("Seller approved — they can now list items");
  };

  const adminAutoVerifySeller = async (application) => {
    if (!window.confirm(`Run automatic record checks and approve @${application.username} if every check passes?`)) return;
    try {
      const response = await authFetch(`${BACKEND_URL}/admin/verified-seller-applications/${application.id}/auto-verify`, { method: "PATCH" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        showToast(data.error || "Automatic verification could not approve this seller");
        return;
      }
      const nextMembers = members.map((member) =>
        member.username === application.username ? backendUserToMember(data.user, member) : member
      );
      await persistMembers(nextMembers);
      fetchVerifiedSellerApplications();
      showToast("Verified Seller automatically approved — all Stallyard record checks passed");
    } catch {
      showToast("Couldn't reach the server — try again");
    }
  };

  const adminRejectMember = async (username, reason) => {
    const target = members.find((m) => m.username === username);
    if (target?.backendId) {
      try {
        const res = await authFetch(`${BACKEND_URL}/users/${target.backendId}/reject`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: reason || "" }),
        });
        if (!res.ok) {
          let message = "Couldn't reject member — try again";
          try { const data = await res.json(); if (data?.error) message = data.error; } catch {}
          showToast(message);
          return;
        }
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
    }
    await persistMembers(
      members.map((m) =>
        m.username === username
          ? { ...m, isApproved: false, verificationStatus: "rejected", rejectionReason: reason || "" }
          : m
      )
    );
    fetchVerifiedSellerApplications();
    showToast("Seller application rejected");
  };

  const adminToggleVerify = async (username) => {
    const target = members.find((m) => m.username === username);
    const nextVerified = !target?.isVerified;
    if (target?.backendId) {
      try {
        const res = await authFetch(`${BACKEND_URL}/users/${target.backendId}/verify`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ isVerified: nextVerified }),
        });
        if (!res.ok) {
          showToast("Couldn't update member — try again");
          return;
        }
      } catch {
        showToast("Couldn't reach the server — try again");
        return;
      }
    }
    await persistMembers(
      members.map((m) => (m.username === username ? { ...m, isVerified: nextVerified } : m))
    );
    showToast(nextVerified ? "Seller verified" : "Verification removed");
  };

  const adminAddMember = async (data) => {
    const username = data.username.trim().toLowerCase();
    if (!username || !data.password || !data.email?.trim() || !data.phone?.trim()) {
      showToast("Enter a username, email, phone, and password");
      return false;
    }
    if (members.some((m) => m.username === username)) {
      showToast("That username is taken");
      return false;
    }
    let res;
    try {
      res = await authFetch(`${BACKEND_URL}/admin/create-member`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password: data.password,
          displayName: data.displayName.trim() || username,
          email: data.email?.trim() || "",
          phone: data.phone?.trim() || "",
          isApproved: true,
        }),
      });
    } catch {
      showToast("Couldn't reach the server — try again");
      return false;
    }
    const responseData = await res.json();
    if (!res.ok) {
      showToast(responseData.error || "Couldn't add that member");
      return false;
    }
    const newMember = {
      ...backendUserToMember(responseData.user),
      firstName: data.firstName.trim(),
      lastName: data.lastName.trim(),
      officeLocation: data.officeLocation.trim(),
    };
    await persistMembers([...members, newMember]);
    showToast(`Member ${newMember.displayName} added`);
    return true;
  };

  const toggleFollow = async (followedUsername) => {
    if (!currentUser) {
      setAuthReturnView(view);
      setView("signin");
      showToast("Sign in to follow sellers");
      return;
    }
    if (currentUser === followedUsername) return;
    const isFollowing = follows.some(
      (f) => f.followerUsername === currentUser && f.followedUsername === followedUsername
    );
    try {
      const res = await authFetch(`${BACKEND_URL}/follows`, {
        method: isFollowing ? "DELETE" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ followerUsername: currentUser, followedUsername }),
      });
      if (!res.ok) {
        showToast("Couldn't update follow status — try again");
        return;
      }
    } catch {
      showToast("Couldn't reach the server — try again");
      return;
    }
    setFollows((prev) =>
      isFollowing
        ? prev.filter((f) => !(f.followerUsername === currentUser && f.followedUsername === followedUsername))
        : [...prev, { followerUsername: currentUser, followedUsername }]
    );
    showToast(isFollowing ? "Unfollowed" : "Following");
  };

  const myListings = listings.filter((l) => l.ownerUsername === currentUser);
  const filteredMyListings =
    manageListingsTab === "all" ? myListings : myListings.filter((l) => l.status === manageListingsTab);
  const mySales = orders
    .filter((o) => o.items.some((i) => i.ownerUsername === currentUser))
    .sort((a, b) => b.createdAt - a.createdAt);
  const filteredMySales =
    salesTab === "all" ? mySales : mySales.filter((o) => getSellerOrderStatus(o, currentUser) === salesTab);

  // Flattened view of just this seller's line items across all their sales,
  // used for the dashboard's order-status breakdown (waiting to ship, in
  // transit, completed, returns/disputes).
  const mySoldItems = mySales.flatMap((o) =>
    o.items
      .filter((i) => i.ownerUsername === currentUser)
      .map((i) => ({ ...i, orderId: o.id, orderCreatedAt: o.createdAt, isDisputed: o.isDisputed }))
  );
  const totalSalesRevenue = mySoldItems
    .filter((i) => i.fulfillmentStatus !== "cancelled")
    .reduce((s, i) => s + Number(i.price) * (i.qty || 1), 0);
  const ordersWaitingToShip = mySoldItems.filter((i) => (i.fulfillmentStatus || "new") === "new").length;
  const ordersInTransit = mySoldItems.filter((i) => i.fulfillmentStatus === "shipped").length;
  const completedOrdersCount = mySoldItems.filter((i) => i.fulfillmentStatus === "delivered").length;
  const activeReturnsDisputes = mySoldItems.filter(
    (i) => i.returnStatus === "requested" || i.isDisputed
  ).length;

  // Seller performance rates — all computed from this seller's own data,
  // no separate backend endpoint needed.
  const ON_TIME_SHIP_WINDOW_MS = 48 * 60 * 60 * 1000;
  const cancellationRate =
    mySoldItems.length > 0
      ? Math.round((mySoldItems.filter((i) => i.fulfillmentStatus === "cancelled").length / mySoldItems.length) * 100)
      : null;
  const returnRate =
    mySoldItems.length > 0
      ? Math.round((mySoldItems.filter((i) => !!i.returnStatus).length / mySoldItems.length) * 100)
      : null;
  const disputeRate =
    mySales.length > 0
      ? Math.round((mySales.filter((o) => o.isDisputed).length / mySales.length) * 100)
      : null;
  const shippedItems = mySoldItems.filter((i) => i.shippedAt);
  const onTimeShippingRate =
    shippedItems.length > 0
      ? Math.round(
          (shippedItems.filter((i) => i.shippedAt - i.orderCreatedAt <= ON_TIME_SHIP_WINDOW_MS).length /
            shippedItems.length) *
            100
        )
      : null;

  const myWalletTx = mySales.flatMap((o) => {
    const myItems = o.items.filter((i) => i.ownerUsername === currentUser);
    return myItems.map((i) => {
      const itemGross = i.price * i.qty;
      const rate = o.commissionRate ?? 0.05;
      const itemShipping = Number(i.shippingFee) || 0;
      const payout =
        o.commissionRate !== undefined
          ? Math.round((itemGross - itemGross * rate + itemShipping) * 100) / 100
          : itemGross;
      const voided = i.fulfillmentStatus === "cancelled" || i.fulfillmentStatus === "returned";
      let walletStatus;
      if (voided) walletStatus = "voided";
      else if (o.paymentStatus === "refunded") walletStatus = "refunded";
      else if (o.paymentStatus === "released") walletStatus = "released";
      else walletStatus = "held";
      return {
        key: `${o.id}-${i.id}`,
        buyerName: o.buyerName,
        createdAt: o.createdAt,
        title: i.title,
        qty: i.qty,
        payout,
        walletStatus,
      };
    });
  });
  const walletAvailable = myWalletTx
    .filter((t) => t.walletStatus === "released")
    .reduce((s, t) => s + t.payout, 0);
  const walletHeld = myWalletTx
    .filter((t) => t.walletStatus === "held")
    .reduce((s, t) => s + t.payout, 0);
  const walletVoided = myWalletTx
    .filter((t) => t.walletStatus === "voided" || t.walletStatus === "refunded")
    .reduce((s, t) => s + t.payout, 0);

  const myWithdrawals = withdrawals
    .filter((w) => w.sellerUsername === currentUser)
    .sort((a, b) => b.requestedAt - a.requestedAt);
  const withdrawalsReserved = myWithdrawals
    .filter((w) => w.status === "processing" || w.status === "paid")
    .reduce((s, w) => s + w.amount, 0);
  const withdrawalsPaidTotal = myWithdrawals
    .filter((w) => w.status === "paid")
    .reduce((s, w) => s + w.amount, 0);
  const walletNetAvailable = Math.max(0, walletAvailable - withdrawalsReserved);

  const myRecentActivity = [
    ...mySales.map((o) => {
      const myItems = o.items.filter((i) => i.ownerUsername === currentUser);
      const total = myItems.reduce((s, i) => s + Number(i.price) * (i.qty || 1), 0);
      return { id: `sale-${o.id}`, message: `New sale from ${o.buyerName} — ${formatMoney(total, "NGN")}`, at: o.createdAt };
    }),
    ...mySales
      .filter((o) => o.isDisputed)
      .map((o) => ({ id: `dispute-${o.id}`, message: `Dispute opened on order from ${o.buyerName}`, at: o.createdAt })),
    ...mySoldItems
      .filter((i) => i.returnStatus === "requested")
      .map((i) => ({ id: `return-${i.id}`, message: `Return requested — ${i.title}`, at: i.returnRequestedAt || Date.now() })),
    ...myWithdrawals
      .filter((w) => w.status === "paid")
      .map((w) => ({ id: `payout-${w.id}`, message: `Payout of ${formatMoney(Number(w.amount), "NGN")} completed`, at: w.requestedAt })),
  ]
    .sort((a, b) => b.at - a.at)
    .slice(0, 5);

  const myOrders = orders
    .filter((o) => o.buyerUsername === currentUser)
    .sort((a, b) => b.createdAt - a.createdAt);

  // Flattened view of everything this buyer has purchased across all their
  // orders, used for the buyer dashboard's status breakdown — mirrors
  // mySoldItems above, just from the buyer's side instead of the seller's.
  const myPurchasedItems = myOrders.flatMap((o) =>
    o.items.map((i) => ({ ...i, orderId: o.id, orderCreatedAt: o.createdAt, isDisputed: o.isDisputed, paymentStatus: o.paymentStatus }))
  );
  const buyerActiveOrdersCount = myOrders.filter((o) =>
    o.paymentStatus === "held" &&
    o.items.some((i) =>
      !["cancelled", "returned"].includes(i.fulfillmentStatus) &&
      !["approved"].includes(i.returnStatus) &&
      !["approved"].includes(i.cancellationStatus)
    )
  ).length;
  const buyerOrdersWaitingToShip = myPurchasedItems.filter((i) =>
    i.paymentStatus === "held" && ["new", "preparing"].includes(i.fulfillmentStatus || "new") &&
    i.returnStatus !== "approved" && i.cancellationStatus !== "approved"
  ).length;
  const buyerOrdersInTransit = myPurchasedItems.filter((i) =>
    i.paymentStatus === "held" && i.fulfillmentStatus === "shipped" &&
    i.returnStatus !== "approved" && i.cancellationStatus !== "approved"
  ).length;
  const buyerCompletedCount = myPurchasedItems.filter((i) =>
    i.paymentStatus === "released" && !["cancelled", "returned"].includes(i.fulfillmentStatus)
  ).length;
  // Count unique order IDs, never dispute rows or order items. Return cases are
  // intentionally excluded from this card because they have their own count.
  const buyerOpenDisputeOrderIds = new Set(
    (myDisputes.length > 0
      ? myDisputes
      .filter((dispute) => ["open", "in_review"].includes(dispute.status))
      .map((dispute) => String(dispute.order_id || dispute.orderId))
      : myOrders.filter((o) => o.isDisputed).map((o) => String(o.id)))
      .filter((id) => id && id !== "undefined")
  );
  const buyerOpenDisputesCount = buyerOpenDisputeOrderIds.size;
  const buyerActiveReturnsDisputes = myOrders.filter((o) =>
    o.isDisputed || o.items.some((i) => ["requested", "approved"].includes(i.returnStatus))
  ).length;
  const buyerPendingReturnsCount = myPurchasedItems.filter((i) => i.returnStatus === "requested").length;
  const buyerTotalSpent = myOrders.reduce((sum, order) => {
    if (order.paymentStatus === "refunded" || (order.refundType === "full" && order.refundStatus === "processed")) return sum;
    const processedRefund = order.refundStatus === "processed" ? Number(order.refundAmount || 0) : 0;
    if (processedRefund > 0) return sum + Math.max(0, Number(order.total || 0) - processedRefund);

    const keptItems = order.items.filter((item) =>
      !["cancelled", "returned"].includes(item.fulfillmentStatus) &&
      item.returnStatus !== "approved" && item.cancellationStatus !== "approved"
    );
    if (keptItems.length === 0) return sum;
    if (keptItems.length === order.items.length) return sum + Number(order.total || 0);

    const keptSubtotal = keptItems.reduce((amount, item) => amount + Number(item.price || 0) * Number(item.qty || 1), 0);
    const keptShipping = keptItems.reduce((amount, item) => amount + Number(item.shippingFee || 0) * Number(item.qty || 1), 0);
    const taxShare = Number(order.subtotal || 0) > 0
      ? Number(order.taxAmount || 0) * (keptSubtotal / Number(order.subtotal))
      : 0;
    return sum + Math.max(0, keptSubtotal + keptShipping + taxShare);
  }, 0);
  const buyerSpentOrderCount = myOrders.filter((order) => {
    if (order.paymentStatus === "refunded" || (order.refundType === "full" && order.refundStatus === "processed")) return false;
    if (order.refundStatus === "processed" && Number(order.refundAmount || 0) >= Number(order.total || 0)) return false;
    return order.items.some((item) => !["cancelled", "returned"].includes(item.fulfillmentStatus) && item.returnStatus !== "approved" && item.cancellationStatus !== "approved");
  }).length;
  const buyerTokensReadyCount = myOrders.reduce(
    (count, order) => count + (order.paymentStatus === "held" && !order.isDisputed
      ? order.items.filter((item) =>
          !!item.deliveryToken &&
          !item.deliveryTokenSentAt &&
          !["cancelled", "returned"].includes(item.fulfillmentStatus) &&
          !["requested", "approved"].includes(item.returnStatus)
        ).length
      : 0),
    0
  );
  const filteredBuyerOrders = myOrders.filter((order) => {
    const query = buyerOrderSearch.trim().toLowerCase();
    const matchesSearch = !query || [
      String(order.id),
      orderNumber(order.id),
      order.paystackReference || "",
      ...order.items.flatMap((item) => [
        item.title || "",
        item.sellerName || "",
        item.ownerUsername || "",
        item.trackingNumber || "",
        item.carrier || "",
      ]),
    ].some((value) => String(value).toLowerCase().includes(query));
    if (!matchesSearch) return false;

    const items = order.items || [];
    if (buyerOrderStatusFilter === "all") return true;
    if (buyerOrderStatusFilter === "active") {
      return order.paymentStatus === "held" && items.some((item) =>
        !["cancelled", "returned"].includes(item.fulfillmentStatus) &&
        item.returnStatus !== "approved" && item.cancellationStatus !== "approved"
      );
    }
    if (buyerOrderStatusFilter === "preparing") {
      return items.some((item) => ["new", "preparing"].includes(item.fulfillmentStatus || "new") && item.returnStatus !== "approved" && item.cancellationStatus !== "approved");
    }
    if (buyerOrderStatusFilter === "shipped") return items.some((item) => item.fulfillmentStatus === "shipped" && item.returnStatus !== "approved" && item.cancellationStatus !== "approved");
    if (buyerOrderStatusFilter === "delivered") return items.some((item) => item.fulfillmentStatus === "delivered");
    if (buyerOrderStatusFilter === "completed") return order.paymentStatus === "released";
    if (buyerOrderStatusFilter === "returned") {
      return items.some((item) => item.fulfillmentStatus === "returned" || ["requested", "approved"].includes(item.returnStatus));
    }
    if (buyerOrderStatusFilter === "refunded") return order.paymentStatus === "refunded" || order.refundStatus === "processed";
    if (buyerOrderStatusFilter === "disputed") return buyerOpenDisputeOrderIds.has(String(order.id));
    return true;
  });
  const unreadNotifCount = notifications.filter((n) => !n.read).length;

  // View-only list of how this buyer has actually paid in the past,
  // deduplicated and sourced straight from real Paystack transactions —
  // not something they manage or add to themselves.
  const myPaymentMethods = (() => {
    const seen = new Map();
    myOrders.forEach((o) => {
      if (!o.paymentChannel) return;
      const key = `${o.paymentChannel}-${o.paymentCardType || ""}-${o.paymentBank || ""}-${o.paymentLast4 || ""}`;
      const existing = seen.get(key);
      if (!existing || o.createdAt > existing.lastUsedAt) {
        seen.set(key, {
          channel: o.paymentChannel,
          cardType: o.paymentCardType,
          bank: o.paymentBank,
          last4: o.paymentLast4,
          lastUsedAt: o.createdAt,
        });
      }
    });
    return Array.from(seen.values()).sort((a, b) => b.lastUsedAt - a.lastUsedAt);
  })();
  const paymentMethodLabel = (m) => {
    if (m.channel === "card") {
      return `${m.cardType ? m.cardType.charAt(0).toUpperCase() + m.cardType.slice(1) : "Card"}${m.last4 ? ` ending in ${m.last4}` : ""}`;
    }
    if (m.channel === "bank_transfer" || m.channel === "bank") {
      return `Bank transfer${m.bank ? ` via ${m.bank}` : ""}`;
    }
    if (m.channel === "ussd") return `USSD${m.bank ? ` via ${m.bank}` : ""}`;
    return m.channel.charAt(0).toUpperCase() + m.channel.slice(1);
  };

  const disputedOrders = orders.filter((o) => o.isDisputed);
  const openAdminDisputes = adminDisputes.filter((d) => d.status !== "resolved");
  const getMyDisputeForOrder = (orderId) => myDisputes.find((d) => Number(d.order_id) === Number(orderId));
  const myThreads = threads
    .filter((t) => t.buyerUsername === currentUser || t.sellerUsername === currentUser)
    .sort((a, b) => b.updatedAt - a.updatedAt);
  const activeThread = threads.find((t) => t.id === activeThreadId) || null;
  const unreadThreadsCount = myThreads.filter((t) => {
    const lastMsg = t.messages[t.messages.length - 1];
    return lastMsg && lastMsg.senderUsername !== currentUser && lastMsg.createdAt > (messageReadState[t.id] || 0);
  }).length;

  const getListingRating = (listingId) => {
    const rs = reviews.filter((r) => r.listingId === listingId);
    if (rs.length === 0) return null;
    const avg = rs.reduce((s, r) => s + r.rating, 0) / rs.length;
    return { avg, count: rs.length };
  };

  const getReviewFor = (orderId, listingId) =>
    reviews.find((r) => r.orderId === orderId && r.listingId === listingId) || null;

  const getSellerVacationInfo = (username) => {
    const seller = members.find((m) => m.username === username);
    if (!seller?.vacationMode) return null;
    return {
      returnDate: seller.vacationReturnDate || "",
      message: seller.vacationMessage || "",
    };
  };

  const getSellerRating = (username) => {
    const rs = reviews.filter((r) => r.sellerUsername === username);
    if (rs.length === 0) return null;
    const avg = rs.reduce((s, r) => s + r.rating, 0) / rs.length;
    return { avg, count: rs.length };
  };

  const needsIdVerification = needsLegacySalesThresholdVerification;

  // eBay-style reputation: 4-5 stars count as positive, 3 as neutral, 1-2 as negative.
  const getSellerReputation = (username) => {
    const rs = reviews.filter((r) => r.sellerUsername === username);
    if (rs.length === 0) return null;
    const positive = rs.filter((r) => r.rating >= 4).length;
    const positivePct = Math.round((positive / rs.length) * 100);
    return { positivePct, count: rs.length };
  };

  const openStorefront = (username) => {
    setViewingSeller(username);
    setSelected(null);
    setView("storefront");
    fetchSellerSalesCount(username);
  };


  const filtered = listings
    .filter((l) => {
      const matchesCategory = categoryFilter === "All" || l.category === categoryFilter;
      const matchesSubcategory = subcategoryFilter === "All" || l.subcategory === subcategoryFilter;
      const matchesCondition = conditionFilter === "All" || (l.condition || "New") === conditionFilter;
      const q = search.trim().toLowerCase();
      const matchesSearch =
        !q || l.title.toLowerCase().includes(q) || l.description.toLowerCase().includes(q);
      const isVisible = l.status === "active";
      const min = priceMin !== "" ? Number(priceMin) : -Infinity;
      const max = priceMax !== "" ? Number(priceMax) : Infinity;
      const matchesPrice = Number(l.price) >= min && Number(l.price) <= max;
      return matchesCategory && matchesSubcategory && matchesCondition && matchesSearch && isVisible && matchesPrice;
    })
    .sort((a, b) => {
      if (sortBy === "price-asc") return Number(a.price) - Number(b.price);
      if (sortBy === "price-desc") return Number(b.price) - Number(a.price);
      if (sortBy === "newest") return (b.createdAt || 0) - (a.createdAt || 0);
      if (sortBy === "rating") {
        const ra = getListingRating(a.id)?.avg || 0;
        const rb = getListingRating(b.id)?.avg || 0;
        return rb - ra;
      }
      // default: featured first
      return (b.isFeatured ? 1 : 0) - (a.isFeatured ? 1 : 0);
    });

  const visibleListings = listings.filter((l) => l.status === "active");
  const featuredPicks = visibleListings.filter((l) => l.isFeatured).slice(0, 10);
  const newArrivals = visibleListings
    .slice()
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
    .slice(0, 10);
  const isHomeState = !search.trim() && categoryFilter === "All" && subcategoryFilter === "All" && !priceMin && !priceMax && conditionFilter === "All";

  const NavButton = ({ id, icon: Icon, label, badge, onClick }) => (
    <button
      onClick={onClick || (() => setView(id))}
      className="relative flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
      style={{
        color: view === id ? INK : "#C9CCD3",
        backgroundColor: view === id ? MARIGOLD : "transparent",
      }}
    >
      <Icon size={16} />
      {label}
      {badge > 0 && (
        <span
          className="absolute -top-1 -right-1 min-w-[16px] h-[16px] px-1 rounded-full text-[10px] font-semibold flex items-center justify-center"
          style={{ backgroundColor: BERRY, color: "white" }}
        >
          {badge}
        </span>
      )}
    </button>
  );

  if (fatalServerError) {
    return <StallyardErrorScreen onRetry={() => window.location.reload()} />;
  }

  if (adminLoginMode) {
    return (
      <div
        className="min-h-screen w-full flex items-center justify-center px-6"
        style={{ backgroundColor: INK, fontFamily: "'Work Sans', sans-serif" }}
      >
        <div className="w-full max-w-sm">
          <div className="flex items-center gap-2 justify-center mb-8">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
              style={{ backgroundColor: MARIGOLD }}
            >
              <span style={{ fontFamily: "'DM Serif Display', serif", color: INK, fontSize: "16px" }}>S</span>
            </div>
            <h1 className="text-xl tracking-wide" style={{ fontFamily: "'DM Serif Display', serif", color: MARIGOLD }}>
              Stallyard Admin
            </h1>
          </div>
          <div className="bg-white rounded-2xl p-6">
            {adminLoginStep === "credentials" ? (
              <>
                <h2 className="text-lg font-semibold mb-1" style={{ color: INK }}>
                  Sign in
                </h2>
                <p className="text-sm mb-4" style={{ color: SLATE }}>
                  Step 1 of 3: enter your admin username and password.
                </p>
                <input
                  value={adminLoginForm.username}
                  onChange={(e) => setAdminLoginForm((f) => ({ ...f, username: e.target.value }))}
                  placeholder="Username"
                  autoCapitalize="none"
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
                <input
                  type="password"
                  value={adminLoginForm.password}
                  onChange={(e) => setAdminLoginForm((f) => ({ ...f, password: e.target.value }))}
                  onKeyDown={(e) => e.key === "Enter" && submitAdminLoginCredentials()}
                  placeholder="Password"
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
                {adminLoginError && (
                  <p className="text-sm mb-2" style={{ color: BERRY }}>
                    {adminLoginError}
                  </p>
                )}
                <button
                  onClick={submitAdminLoginCredentials}
                  disabled={adminLoginSubmitting}
                  className="w-full py-2.5 rounded-lg font-medium mt-1 disabled:opacity-50"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {adminLoginSubmitting ? "Checking..." : "Continue"}
                </button>
              </>
            ) : adminLoginStep === "new-password" ? (
              <>
                <h2 className="text-lg font-semibold mb-1" style={{ color: INK }}>
                  Set a new password
                </h2>
                <p className="text-sm mb-4" style={{ color: SLATE }}>
                  Your 10-minute temporary password was accepted and all three security checks passed. Choose a new permanent admin password to finish signing in.
                </p>
                <input
                  type="password"
                  value={adminTempNewPasswordForm.password}
                  onChange={(e) => setAdminTempNewPasswordForm((f) => ({ ...f, password: e.target.value }))}
                  placeholder="New password"
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                  autoFocus
                />
                <input
                  type="password"
                  value={adminTempNewPasswordForm.confirm}
                  onChange={(e) => setAdminTempNewPasswordForm((f) => ({ ...f, confirm: e.target.value }))}
                  onKeyDown={(e) => e.key === "Enter" && completeAdminTemporaryPassword()}
                  placeholder="Confirm new password"
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
                {adminLoginError && (
                  <p className="text-sm mb-2" style={{ color: BERRY }}>{adminLoginError}</p>
                )}
                <button
                  onClick={completeAdminTemporaryPassword}
                  disabled={adminLoginSubmitting}
                  className="w-full py-2.5 rounded-lg font-medium mt-1 disabled:opacity-50"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {adminLoginSubmitting ? "Saving..." : "Set password & sign in"}
                </button>
              </>
            ) : (
              <>
                <h2 className="text-lg font-semibold mb-1" style={{ color: INK }}>
                  Enter your code
                </h2>
                <p className="text-sm mb-4" style={{ color: SLATE }}>
                  {adminLoginStep === "code-email"
                    ? "Step 3 of 3: enter the 6-digit code we just emailed you."
                    : "Step 2 of 3: enter the 6-digit code from your authenticator app. An email code comes next."}
                </p>
                <input
                  value={adminLoginCode}
                  onChange={(e) => setAdminLoginCode(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && submitAdminLoginTwoFactor()}
                  placeholder="6-digit code"
                  maxLength={6}
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-center text-lg tracking-widest"
                  style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                  autoFocus
                />
                {adminLoginError && (
                  <p className="text-sm mb-2" style={{ color: BERRY }}>
                    {adminLoginError}
                  </p>
                )}
                <button
                  onClick={submitAdminLoginTwoFactor}
                  disabled={adminLoginSubmitting}
                  className="w-full py-2.5 rounded-lg font-medium mt-1 disabled:opacity-50"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {adminLoginSubmitting ? "Verifying..." : adminLoginStep === "code-email" ? "Sign in" : "Continue"}
                </button>
                <button
                  onClick={() => {
                    setAdminLoginStep("credentials");
                    setAdminLoginCode("");
                    setAdminLoginError("");
                    setAdminTempPasswordChangeToken("");
                    setAdminTempNewPasswordForm({ password: "", confirm: "" });
                  }}
                  className="text-xs font-medium underline mt-3"
                  style={{ color: SLATE }}
                >
                  ← Back
                </button>
              </>
            )}
          </div>
          <button
            onClick={() => window.location.assign("https://stallyard.com")}
            className="text-xs font-medium underline mt-4 block mx-auto"
            style={{ color: "#8A93A3" }}
          >
            ← Go to public marketplace
          </button>
        </div>
      </div>
    );
  }

  if (PRIVATE_VIEWS.has(view) && (!sessionChecked || !currentUser)) {
    return <div role="status" className="min-h-screen flex items-center justify-center" style={{ backgroundColor: CANVAS, color: INK }}>Checking your session…</div>;
  }

  if (view === "signup" || view === "signin") {
    const isSignUp = view === "signup";
    return (
      <div className="min-h-screen w-full flex" style={{ backgroundColor: "white", fontFamily: "'Work Sans', sans-serif" }}>
        {/* Photo panel */}
        <div
          className="hidden lg:block lg:w-1/2 relative"
          style={{ backgroundColor: CANVAS }}
        >
          <div
            className="absolute inset-6 rounded-2xl bg-cover bg-center"
            style={{
              backgroundImage:
                `linear-gradient(135deg, rgba(27,36,48,0.15), rgba(27,36,48,0.35)), url('${
                  settings.authImage ||
                  "https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=1200&q=80"
                }')`,
            }}
          />
        </div>

        {/* Form panel */}
        <div className="flex-1 flex flex-col">
          <div className="flex items-center justify-between px-6 sm:px-10 py-5">
            <button
              onClick={() => setView(authReturnView)}
              className="flex items-center gap-2"
            >
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
                style={{ backgroundColor: MARIGOLD }}
              >
                <Store size={16} style={{ color: INK }} />
              </div>
              <span className="text-lg" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                Stallyard
              </span>
            </button>
            <p className="text-sm" style={{ color: SLATE }}>
              {isSignUp ? "Already have an account? " : "New to Stallyard? "}
              <button
                onClick={() => {
                  setAuthMode(isSignUp ? "login" : "register");
                  setAuthError("");
                  setView(isSignUp ? "signin" : "signup");
                }}
                className="font-medium underline"
                style={{ color: INK }}
              >
                {isSignUp ? "Sign in" : "Create an account"}
              </button>
            </p>
          </div>

          <div className="flex-1 flex items-start sm:items-center justify-center px-6 sm:px-10 pb-10">
            <div className="w-full max-w-sm">
              {pendingTwoFactor ? (
                <div>
                  <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                    Enter your code
                  </h1>
                  <p className="text-sm mb-4" style={{ color: SLATE }}>
                    {pendingTwoFactor.method === "totp"
                      ? "Enter the 6-digit code from your authenticator app. (1 of 2 — an email code comes next.)"
                      : pendingTwoFactor.method === "totp-email"
                      ? "Now enter the 6-digit code we just emailed you. (2 of 2)"
                      : "We emailed a 6-digit code to confirm it's really you."}
                  </p>
                  <input
                    value={twoFactorCodeInput}
                    onChange={(e) => setTwoFactorCodeInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && verifyTwoFactorCode()}
                    placeholder="6-digit code"
                    maxLength={6}
                    className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-center text-lg tracking-widest"
                    style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                  />
                  {authError && (
                    <p className="text-sm mb-2" style={{ color: BERRY }}>
                      {authError}
                    </p>
                  )}
                  <button
                    type="button"
                    onClick={verifyTwoFactorCode}
                    className="w-full py-2.5 rounded-lg font-medium mt-1"
                    style={{ backgroundColor: MARIGOLD, color: INK }}
                  >
                    {pendingTwoFactor.method === "totp" ? "Continue" : "Verify & log in"}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setPendingTwoFactor(null);
                      setTwoFactorCodeInput("");
                      setAuthError("");
                    }}
                    className="text-xs font-medium underline mt-3"
                    style={{ color: SLATE }}
                  >
                    ← Back
                  </button>
                </div>
              ) : pendingEmailVerification ? (
                <div>
                  <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                    Verify your email
                  </h1>
                  <p className="text-sm mb-4" style={{ color: SLATE }}>
                    We just emailed a 6-digit code to{" "}
                    <strong style={{ color: INK }}>{pendingEmailVerification.signupDraft.email}</strong>.
                    Enter it below to finish creating your account.
                  </p>
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Enter the 6-digit code
                  </label>
                  <input
                    value={emailCodeInput}
                    onChange={(e) => {
                      setEmailCodeInput(e.target.value);
                      if (emailVerifyError) setEmailVerifyError("");
                    }}
                    onKeyDown={(e) => e.key === "Enter" && confirmEmailCode()}
                    placeholder="123456"
                    className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-center text-lg tracking-widest"
                    style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                  />
                  {emailVerifyError && (
                    <p className="text-sm mb-2" style={{ color: BERRY }}>
                      {emailVerifyError}
                    </p>
                  )}
                  <button
                    type="button"
                    onClick={confirmEmailCode}
                    className="w-full py-2.5 rounded-lg font-medium mt-1"
                    style={{ backgroundColor: MARIGOLD, color: INK }}
                  >
                    Verify & create account
                  </button>
                  <div className="flex items-center justify-between mt-3">
                    <button
                      type="button"
                      onClick={resendEmailCode}
                      className="text-xs font-medium underline"
                      style={{ color: SLATE }}
                    >
                      Resend code
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setPendingEmailVerification(null);
                        setEmailCodeInput("");
                        setEmailVerifyError("");
                      }}
                      className="text-xs font-medium underline"
                      style={{ color: SLATE }}
                    >
                      ← Back
                    </button>
                  </div>
                </div>
              ) : accountCreatedSuccess ? (
                <div role="status" aria-live="polite">
                  <div className="w-16 h-16 rounded-full flex items-center justify-center text-3xl mb-5" style={{ backgroundColor: "#EDF4EE", color: SAGE }}>✓</div>
                  <h1 className="text-3xl mb-2" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Account created successfully</h1>
                  <p className="text-sm mb-5 leading-6" style={{ color: SLATE }}>Welcome to Stallyard. Your email is verified, your profile has been saved, and you are securely signed in.</p>
                  <div className="rounded-xl border p-4 mb-5 space-y-2 text-sm" style={{ borderColor: "#DDD8CC", backgroundColor: "#FAF8F2", color: INK }}>
                    <p>✓ Account created</p>
                    <p>✓ Email verified</p>
                    <p>✓ Personal profile completed</p>
                    <p style={{ color: sessionUserProfile?.is_phone_verified ? SAGE : SLATE }}>{sessionUserProfile?.is_phone_verified ? "✓ Phone verified" : "○ Phone verification still required before selling"}</p>
                  </div>
                  {registrationIntent === "seller" ? (
                    <>
                      <p className="text-sm mb-4" style={{ color: SLATE }}>Next, verify your phone, add your payout bank and complete the secure Casual Seller identity check.</p>
                      <button type="button" onClick={() => { setAccountCreatedSuccess(false); setView("sell"); }} className="w-full py-3 rounded-lg font-semibold" style={{ backgroundColor: MARIGOLD, color: INK }}>Continue seller setup</button>
                      <button type="button" onClick={() => { setAccountCreatedSuccess(false); setView("buyerHome"); }} className="w-full mt-3 py-2 text-sm underline" style={{ color: SLATE }}>Go to dashboard</button>
                    </>
                  ) : (
                    <>
                      <button type="button" onClick={() => { setAccountCreatedSuccess(false); setView("buyerHome"); }} className="w-full py-3 rounded-lg font-semibold" style={{ backgroundColor: MARIGOLD, color: INK }}>Go to Buyer Dashboard</button>
                      <button type="button" onClick={() => { setAccountCreatedSuccess(false); setView("browse"); }} className="w-full mt-3 py-2 text-sm underline" style={{ color: SLATE }}>Start shopping</button>
                    </>
                  )}
                </div>
              ) : profileStageOpen ? (
                <div>
                  <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                    Finish your profile
                  </h1>
                  <p className="text-sm mb-6" style={{ color: SLATE }}>
                    You're signed in. Complete these details to unlock buying and selling, or finish later and continue browsing.
                  </p>
                  <div className="space-y-3">
                    <select
                      value={authForm.country}
                      onChange={(e) => setAuthForm({ ...authForm, country: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                      style={{ borderColor: "#DDD8CC", color: authForm.country ? INK : SLATE }}
                    >
                      <option value="">Country of residence</option>
                      <option value="Nigeria">Nigeria</option>
                    </select>
                    <div className="p-3 rounded-lg border" style={{ borderColor: MARIGOLD, backgroundColor: "#FFF8E8" }}>
                      <p className="text-sm font-semibold" style={{ color: INK }}>
                        Enter your bank-account name exactly
                      </p>
                      <p className="text-xs mt-1" style={{ color: SLATE }}>
                        Your surname, first name and any other name must match the name registered on your bank account. A small spelling difference may cause Stallyard to reject the account during buying, selling or payout verification.
                      </p>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="flex-1">
                        <input
                          value={authForm.lastName}
                          onChange={(e) => setAuthForm({ ...authForm, lastName: e.target.value })}
                          placeholder="Surname"
                          className="w-full px-3 py-2 rounded-lg border outline-none"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                      </div>
                      <div className="flex-1">
                        <input
                          value={authForm.firstName}
                          onChange={(e) => setAuthForm({ ...authForm, firstName: e.target.value })}
                          placeholder="First Name"
                          className="w-full px-3 py-2 rounded-lg border outline-none"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                      </div>
                      <div className="flex-1">
                        <input
                          value={authForm.otherName}
                          onChange={(e) => setAuthForm({ ...authForm, otherName: e.target.value })}
                          placeholder="Other Name (optional)"
                          className="w-full px-3 py-2 rounded-lg border outline-none"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <label className="text-xs" style={{ color: SLATE }}>
                        Date of Birth
                        <input
                          type="date"
                          max={new Date(Date.UTC(new Date().getUTCFullYear() - 18, new Date().getUTCMonth(), new Date().getUTCDate())).toISOString().slice(0, 10)}
                          value={authForm.dateOfBirth}
                          onChange={(e) => setAuthForm({ ...authForm, dateOfBirth: e.target.value })}
                          className="block w-full mt-1 px-3 py-2 rounded-lg border outline-none"
                          style={{ borderColor: "#DDD8CC", color: INK }}
                        />
                      </label>
                      <label className="text-xs" style={{ color: SLATE }}>
                        Gender
                        <select
                          value={authForm.gender}
                          onChange={(e) => setAuthForm({ ...authForm, gender: e.target.value })}
                          className="block w-full mt-1 px-3 py-2 rounded-lg border outline-none"
                          style={{ borderColor: "#DDD8CC", color: authForm.gender ? INK : SLATE }}
                        >
                          <option value="">Select gender</option>
                          <option value="male">Male</option>
                          <option value="female">Female</option>
                          <option value="prefer_not_to_say">Prefer not to say</option>
                        </select>
                      </label>
                    </div>
                    <input
                      value={authForm.nationality}
                      onChange={(e) => setAuthForm({ ...authForm, nationality: e.target.value })}
                      placeholder="Nationality"
                      className="w-full px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <select
                      value={authForm.stateOfResidence}
                      onChange={(e) => setAuthForm({ ...authForm, stateOfResidence: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                      style={{ borderColor: "#DDD8CC", color: authForm.stateOfResidence ? INK : SLATE }}
                    >
                      <option value="">Select state of residence</option>
                      {NIGERIAN_STATES.map((state) => <option key={state} value={state}>{state}</option>)}
                    </select>
                    <input
                      type="tel"
                      value={authForm.phone}
                      onChange={(e) => setAuthForm({ ...authForm, phone: e.target.value })}
                      placeholder="Nigerian phone number"
                      className="w-full px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    {profileStageError && (
                      <p className="text-sm" style={{ color: BERRY }}>
                        {profileStageError}
                      </p>
                    )}
                    <button
                      type="button"
                      onClick={completeProfile}
                      className="w-full py-2.5 rounded-lg font-medium mt-1"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      Save & continue
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setProfileStageOpen(false);
                        setView(authReturnView);
                      }}
                      className="text-xs font-medium underline text-center w-full"
                      style={{ color: SLATE }}
                    >
                      I'll finish this later
                    </button>
                  </div>
                </div>
              ) : authMode === "forgot" ? (
                <div>
                  {!pendingPasswordReset ? (
                    <>
                      <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                        Reset your password
                      </h1>
                      <p className="text-sm mb-4" style={{ color: SLATE }}>
                        Enter your username and we'll email a code to the address on file.
                      </p>
                      <input
                        value={resetIdentifier}
                        onChange={(e) => {
                          setResetIdentifier(e.target.value);
                          if (resetError) setResetError("");
                        }}
                        onKeyDown={(e) => e.key === "Enter" && requestPasswordReset()}
                        placeholder="Username"
                        className="w-full mb-2 px-3 py-2 rounded-lg border outline-none"
                        style={{ borderColor: "#DDD8CC" }}
                        autoCapitalize="none"
                      />
                      {resetError && (
                        <p className="text-sm mb-2" style={{ color: BERRY }}>
                          {resetError}
                        </p>
                      )}
                      <button
                        type="button"
                        onClick={requestPasswordReset}
                        className="w-full py-2.5 rounded-lg font-medium mt-1"
                        style={{ backgroundColor: MARIGOLD, color: INK }}
                      >
                        Send reset code
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setAuthMode("login");
                          setResetError("");
                        }}
                        className="text-xs font-medium underline mt-3"
                        style={{ color: SLATE }}
                      >
                        ← Back to sign in
                      </button>
                    </>
                  ) : !pendingPasswordReset.verified ? (
                    <>
                      <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                        Enter your code
                      </h1>
                      <p className="text-sm mb-4" style={{ color: SLATE }}>
                        We sent a code to {pendingPasswordReset.maskedEmail || "the email on file"}. Enter it below.
                      </p>
                      <input
                        value={resetCodeInput}
                        onChange={(e) => {
                          setResetCodeInput(e.target.value);
                          if (resetError) setResetError("");
                        }}
                        onKeyDown={(e) => e.key === "Enter" && confirmResetCode()}
                        placeholder="123456"
                        className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-center text-lg tracking-widest"
                        style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                      />
                      {resetError && (
                        <p className="text-sm mb-2" style={{ color: BERRY }}>
                          {resetError}
                        </p>
                      )}
                      <button
                        type="button"
                        onClick={confirmResetCode}
                        className="w-full py-2.5 rounded-lg font-medium mt-1"
                        style={{ backgroundColor: MARIGOLD, color: INK }}
                      >
                        Verify code
                      </button>
                      <div className="flex items-center justify-between mt-3">
                        <button
                          type="button"
                          onClick={resendResetCode}
                          className="text-xs font-medium underline"
                          style={{ color: SLATE }}
                        >
                          Resend code
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setPendingPasswordReset(null);
                            setResetCodeInput("");
                            setResetError("");
                          }}
                          className="text-xs font-medium underline"
                          style={{ color: SLATE }}
                        >
                          ← Back
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                        Set a new password
                      </h1>
                      <p className="text-sm mb-4" style={{ color: SLATE }}>
                        Choose a new password for @{pendingPasswordReset.username}.
                      </p>
                      <div className="space-y-3">
                        <div>
                          <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                            New password
                          </label>
                          <input
                            type="password"
                            value={newPasswordForm.password}
                            onChange={(e) => setNewPasswordForm({ ...newPasswordForm, password: e.target.value })}
                            className="w-full px-3 py-2 rounded-lg border outline-none"
                            style={{ borderColor: "#DDD8CC" }}
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                            Confirm password
                          </label>
                          <input
                            type="password"
                            value={newPasswordForm.confirm}
                            onChange={(e) => setNewPasswordForm({ ...newPasswordForm, confirm: e.target.value })}
                            className="w-full px-3 py-2 rounded-lg border outline-none"
                            style={{ borderColor: "#DDD8CC" }}
                          />
                        </div>
                        {resetError && (
                          <p className="text-sm" style={{ color: BERRY }}>
                            {resetError}
                          </p>
                        )}
                        <button
                          type="button"
                          onClick={submitNewPassword}
                          className="w-full py-2.5 rounded-lg font-medium mt-1"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          Update password
                        </button>
                      </div>
                    </>
                  )}
                </div>
              ) : (
                <>
                  <h1 className="text-3xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                    {isSignUp ? "Create an account" : "Welcome back"}
                  </h1>
                  <p className="text-sm mb-6" style={{ color: SLATE }}>
                    {isSignUp
                      ? "Just a username, email, and password to get started — you can add the rest later."
                      : "Sign in to manage your stall and listings."}
                  </p>

                  {isSignUp && (
                    <div className="p-3 rounded-lg border mb-4" style={{ borderColor: MARIGOLD, backgroundColor: "#FFF8E8" }}>
                      <p className="text-sm font-semibold" style={{ color: INK }}>
                        Use the exact name on your bank account
                      </p>
                      <p className="text-xs mt-1" style={{ color: SLATE }}>
                        After signup, enter your Surname and First Name exactly as your bank has them. Even a small spelling difference can cause Stallyard to reject your bank account during buying/selling/payout verification.
                      </p>
                    </div>
                  )}

                  <form
                    className="space-y-3"
                    onSubmit={(event) => {
                      event.preventDefault();
                      if (isSignUp) register();
                      else login();
                    }}
                  >
                    <input
                      value={authForm.username}
                      onChange={(e) => setAuthForm({ ...authForm, username: e.target.value })}
                      placeholder={isSignUp ? "Username" : "Username or email"}
                      className="w-full px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                      autoCapitalize="none"
                      autoComplete="username"
                    />
                    {isSignUp && (
                      <input
                        type="email"
                        value={authForm.email}
                        onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                        placeholder="Email"
                        className="w-full px-3 py-2 rounded-lg border outline-none"
                        style={{ borderColor: "#DDD8CC" }}
                        autoCapitalize="none"
                      />
                    )}
                    <div className="relative">
                      <input
                        type={showAuthPassword ? "text" : "password"}
                        value={authForm.password}
                        onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                        placeholder="Password"
                        className="w-full px-3 py-2 pr-12 rounded-lg border outline-none"
                        style={{ borderColor: "#DDD8CC" }}
                        autoComplete={isSignUp ? "new-password" : "current-password"}
                      />
                      <button
                        type="button"
                        onClick={() => setShowAuthPassword((visible) => !visible)}
                        className="absolute inset-y-0 right-0 px-3 flex items-center justify-center"
                        style={{ color: SLATE }}
                        aria-label={showAuthPassword ? "Hide password" : "Show password"}
                        aria-pressed={showAuthPassword}
                        title={showAuthPassword ? "Hide password" : "Show password"}
                      >
                        {showAuthPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                    {!isSignUp && (
                      <button
                        type="button"
                        onClick={() => {
                          setAuthMode("forgot");
                          setAuthError("");
                          setResetIdentifier("");
                          setResetError("");
                        }}
                        className="text-xs font-medium underline"
                        style={{ color: SLATE }}
                      >
                        Forgot password?
                      </button>
                    )}
                    {authError && (
                      <p className="text-sm" style={{ color: BERRY }}>
                        {authError}
                      </p>
                    )}
                    <button
                      type="submit"
                      className="w-full py-2.5 rounded-lg font-medium mt-1"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      {isSignUp ? "Continue" : "Sign in"}
                    </button>
                  </form>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full" style={{ backgroundColor: CANVAS, fontFamily: "'Work Sans', sans-serif" }}>
      {adminTempPasswordResult && (
        <div className="fixed inset-0 flex items-center justify-center p-4" style={{ backgroundColor: "rgba(27,36,48,0.70)", zIndex: 99999 }}>
          <div className="w-full max-w-lg rounded-2xl bg-white shadow-2xl border p-5" style={{ borderColor: MARIGOLD }}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-xl font-semibold" style={{ color: INK }}>10-minute temporary admin password</div>
                <p className="text-sm mt-1" style={{ color: SLATE }}>
                  For <strong>@{adminTempPasswordResult.username}</strong>. Copy it now.
                </p>
              </div>
              <button onClick={() => setAdminTempPasswordResult(null)} className="w-9 h-9 rounded-full border flex items-center justify-center shrink-0" style={{ borderColor: "#DDD8CC", color: SLATE }} aria-label="Close temporary password">
                <X size={18} />
              </button>
            </div>
            <div className="mt-5 p-4 rounded-xl border" style={{ borderColor: "#DDD8CC", backgroundColor: CANVAS }}>
              <div className="text-xs font-medium mb-2" style={{ color: SLATE }}>TEMPORARY PASSWORD</div>
              <code className="block text-xl sm:text-2xl font-semibold break-all select-all" style={{ color: INK }}>
                {adminTempPasswordResult.temporaryPassword || "Password was not returned — generate a new one"}
              </code>
            </div>
            {adminTempPasswordResult.expiresAt && (
              <p className="text-sm mt-3" style={{ color: SLATE }}>
                Expires at {new Date(adminTempPasswordResult.expiresAt).toLocaleTimeString()}.
              </p>
            )}
            <div className="flex gap-2 mt-5 flex-wrap">
              <button onClick={async () => {
                try {
                  await navigator.clipboard.writeText(adminTempPasswordResult.temporaryPassword || "");
                  showToast("Temporary password copied");
                } catch {
                  window.prompt("Copy the temporary password", adminTempPasswordResult.temporaryPassword || "");
                }
              }} className="px-4 py-2.5 rounded-lg text-sm font-medium" style={{ backgroundColor: INK, color: "white" }}>
                Copy password
              </button>
              <button onClick={() => setAdminTempPasswordResult(null)} className="px-4 py-2.5 rounded-lg border text-sm font-medium" style={{ borderColor: "#DDD8CC", color: INK }}>
                I saved it — close
              </button>
            </div>
            <p className="text-xs mt-4" style={{ color: BERRY }}>
              This password is valid for 10 minutes and will only be shown during this recovery action.
            </p>
          </div>
        </div>
      )}

      {/* Header */}
      {isAdminHost() ? (
        <header style={{ backgroundColor: INK }} className="sticky top-0 z-20">
          <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
            <button
              onClick={() => { setSelected(null); setView("admin"); }}
              className="flex items-center gap-2"
              aria-label="Admin dashboard"
            >
              <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ backgroundColor: MARIGOLD }}>
                <span style={{ fontFamily: "'DM Serif Display', serif", color: INK, fontSize: "16px" }}>S</span>
              </div>
              <h1 className="text-2xl tracking-wide" style={{ fontFamily: "'DM Serif Display', serif", color: MARIGOLD }}>
                Stallyard Admin
              </h1>
            </button>
            <div className="flex items-center gap-2">
              {currentMember?.isAdmin && (
                <span className="hidden sm:inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium" style={{ backgroundColor: "#2A3442", color: "#C9CCD3" }}>
                  <Shield size={16} />
                  {ADMIN_ROLE_LABELS[currentMember.adminRole || "super_admin"] || "Admin"}
                </span>
              )}
              {currentUser && (
                <>
                  <span className="text-sm hidden sm:inline" style={{ color: "#C9CCD3" }}>{currentMember?.displayName}</span>
                  <button onClick={logout} aria-label="Log out" className="p-2 rounded-lg" style={{ color: "#C9CCD3" }}>
                    <LogOut size={16} />
                  </button>
                </>
              )}
            </div>
          </div>
        </header>
      ) : (
        <header className="sticky top-0 z-20 bg-white border-b" style={{ borderColor: "#E5E0D6" }}>
          {/* Utility bar */}
          <div className="border-b" style={{ borderColor: "#EEEAE1" }}>
            <div className="max-w-[1500px] mx-auto px-4 h-8 flex items-center justify-between text-xs" style={{ color: INK }}>
              <div className="flex items-center gap-4 min-w-0">
                {!currentUser ? (
                  <span className="whitespace-nowrap">
                    Hi!{' '}
                    <button
                      onClick={() => { setAuthMode("login"); setAuthError(""); setAuthReturnView(view); setView("signup"); }}
                      className="underline font-medium"
                      style={{ color: "#2457A6" }}
                    >
                      Sign in
                    </button>
                    {' '}or{' '}
                    <button
                      onClick={() => { setAuthMode("register"); setAuthError(""); setAuthReturnView(view); setView("signup"); }}
                      className="underline font-medium"
                      style={{ color: "#2457A6" }}
                    >
                      register
                    </button>
                  </span>
                ) : (
                  <span className="whitespace-nowrap">Hi, {currentMember?.displayName || currentUser}</span>
                )}
                <button onClick={() => { setView("browse"); setSortBy("featured"); }} className="hidden sm:inline hover:underline">Deals</button>
                <button onClick={() => { setView("browse"); setSortBy("newest"); }} className="hidden md:inline hover:underline">New arrivals</button>
                <button onClick={() => setView("help")} className="hidden sm:inline hover:underline">Help & Contact</button>
              </div>

              <div className="flex items-center gap-3 sm:gap-5 whitespace-nowrap">
                {!currentMember?.isAdmin && <button onClick={() => setView("sell")} className="hover:underline">Sell</button>}
                <button
                  onClick={() => currentUser ? setView("watchlist") : (setAuthMode("login"), setAuthError(""), setAuthReturnView("watchlist"), setView("signup"))}
                  className="hidden sm:inline hover:underline"
                >
                  Watchlist
                </button>
                <button
                  onClick={() => currentUser ? setView("buyerHome") : (setAuthMode("login"), setAuthError(""), setAuthReturnView("buyerHome"), setView("signup"))}
                  className="hidden sm:inline hover:underline"
                >
                  My Stallyard
                </button>
                <a href="/driver/dashboard" className="hidden lg:inline hover:underline">Drive &amp; earn</a>
                {currentUser && !currentMember?.isAdmin && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelected(null);
                      setView("dashboard");
                      window.scrollTo({ top: 0, behavior: "smooth" });
                    }}
                    className="inline-flex items-center gap-1 hover:underline"
                    aria-label="Open seller dashboard"
                    title="Seller Dashboard"
                  >
                    <Store size={16} />
                    <span className="hidden md:inline">Seller Dashboard</span>
                  </button>
                )}
                {currentUser && (
                  <button
                    type="button"
                    onClick={() => setView("wallet")}
                    className="hidden sm:inline-flex items-center gap-1 hover:underline"
                  >
                    <Wallet size={15} />
                    Seller wallet
                  </button>
                )}
                {currentUser && (
                  <button onClick={() => setNotifPanelOpen((o) => !o)} className="relative p-1" aria-label="Notifications">
                    <Bell size={18} />
                    {notifications.some((n) => !n.read) && (
                      <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full text-[9px] text-white flex items-center justify-center" style={{ backgroundColor: BERRY }}>
                        {notifications.filter((n) => !n.read).length}
                      </span>
                    )}
                  </button>
                )}
                <button onClick={() => setCartOpen(true)} className="relative p-1" aria-label="Open cart">
                  <ShoppingBag size={19} />
                  {cartCount > 0 && (
                    <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full text-[9px] text-white flex items-center justify-center" style={{ backgroundColor: BERRY }}>
                      {cartCount}
                    </span>
                  )}
                </button>
                {currentUser && (
                  <button
                    type="button"
                    onClick={logout}
                    className="lg:hidden relative p-1"
                    aria-label="Log out"
                    title="Log out"
                  >
                    <LogOut size={19} />
                  </button>
                )}
                {currentUser && (
                  <button onClick={logout} className="hidden lg:inline hover:underline">Log out</button>
                )}
              </div>
            </div>
          </div>

          {/* Main search row */}
          <div className="max-w-[1500px] mx-auto px-4 py-3 flex items-center gap-3">
            <button
              onClick={() => { setSelected(null); setCategoryFilter("All"); setSearch(""); setView("browse"); }}
              className="flex items-center gap-2 shrink-0"
              aria-label="Go to Stallyard home"
            >
              <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: MARIGOLD }}>
                <span style={{ fontFamily: "'DM Serif Display', serif", color: INK, fontSize: "20px" }}>S</span>
              </div>
              <span className="hidden sm:block text-2xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Stallyard</span>
            </button>

            <div className="relative shrink-0" ref={categoriesMenuRef}>
              <button
                type="button"
                onClick={() => setCategoriesMenuOpen((open) => !open)}
                className="hidden md:flex items-center gap-2 px-2 py-2 text-xs leading-tight text-left"
                style={{ color: SLATE }}
                aria-haspopup="menu"
                aria-expanded={categoriesMenuOpen}
              >
                <span>Shop by<br />category</span>
                <span aria-hidden="true">⌄</span>
              </button>
              <button
                type="button"
                onClick={() => setCategoriesMenuOpen((open) => !open)}
                className="md:hidden p-2 rounded-full border"
                style={{ borderColor: "#DDD8CC", color: INK }}
                aria-label="Open categories"
              >
                <LayoutGrid size={18} />
              </button>

              {categoriesMenuOpen && (
                <div
                  className="absolute left-0 top-full mt-2 w-[330px] max-w-[88vw] bg-white rounded-xl shadow-2xl border overflow-hidden"
                  style={{ borderColor: "#DDD8CC", zIndex: 80 }}
                  role="menu"
                  aria-label="Marketplace categories"
                >
                  <div className="max-h-[560px] overflow-y-auto py-2">
                    <button
                      type="button"
                      onClick={() => { setCategoryFilter("All"); setSubcategoryFilter("All"); setView("browse"); setCategoriesMenuOpen(false); }}
                      className="w-full flex items-center justify-between gap-3 px-5 py-3 text-left text-sm transition-colors hover:bg-[#F6F3EC]"
                      style={{ color: INK, backgroundColor: categoryFilter === "All" ? "#F6F3EC" : "white" }}
                      role="menuitem"
                    >
                      <span className="font-medium">All Categories</span>
                      {categoryFilter === "All" && <span style={{ color: MARIGOLD }}>●</span>}
                    </button>
                    {CATEGORIES.map((category) => (
                      <button
                        key={category}
                        type="button"
                        onClick={() => { setCategoryFilter(category); setSubcategoryFilter("All"); setView("browse"); setSelected(null); setCategoriesMenuOpen(false); }}
                        className="w-full flex items-center justify-between gap-3 px-5 py-3 text-left text-sm transition-colors hover:bg-[#F6F3EC]"
                        style={{ color: INK, backgroundColor: categoryFilter === category ? "#F6F3EC" : "white" }}
                        role="menuitem"
                      >
                        <span>{category}</span>
                        {categoryFilter === category && <span style={{ color: MARIGOLD }}>●</span>}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex-1 min-w-0 flex items-stretch border-2 rounded-full overflow-hidden bg-white" style={{ borderColor: INK }}>
              <div className="relative flex-1 min-w-0">
                <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: SLATE }} />
                <input
                  value={search}
                  onChange={(e) => { setSearch(e.target.value); if (view !== "browse") setView("browse"); }}
                  onFocus={() => setCategoriesMenuOpen(false)}
                  onKeyDown={(e) => { if (e.key === "Enter") { setView("browse"); setSelected(null); } }}
                  placeholder="Search for anything"
                  className="w-full pl-11 pr-3 py-2.5 outline-none text-sm bg-white"
                  style={{ color: INK }}
                  aria-label="Search marketplace"
                />
              </div>
              <select
                value={categoryFilter}
                onChange={(e) => { setCategoryFilter(e.target.value); setSubcategoryFilter("All"); setView("browse"); setSelected(null); }}
                className="hidden lg:block max-w-[185px] px-4 border-l outline-none bg-white text-sm"
                style={{ borderColor: "#DDD8CC", color: SLATE }}
                aria-label="Search category"
              >
                <option value="All">All Categories</option>
                {CATEGORIES.map((category) => <option key={category} value={category}>{category}</option>)}
              </select>
            </div>

            <button
              onClick={() => { setView("browse"); setSelected(null); }}
              className="shrink-0 px-5 sm:px-8 py-2.5 rounded-full text-sm font-semibold"
              style={{ backgroundColor: MARIGOLD, color: INK }}
            >
              Search
            </button>
          </div>

          {/* Quick category strip */}
          <div className="border-t" style={{ borderColor: "#EEEAE1" }}>
            <div className="max-w-[1500px] mx-auto px-4 flex items-center gap-7 overflow-x-auto whitespace-nowrap py-2 text-xs" style={{ color: INK }}>
              <button
                onClick={() => { setCategoryFilter("All"); setSubcategoryFilter("All"); setView("browse"); setSelected(null); }}
                className="px-3 py-1 rounded-full font-medium shrink-0"
                style={{ backgroundColor: categoryFilter === "All" ? "#F4F1EA" : "transparent" }}
              >
                All
              </button>
              {CATEGORIES.slice(0, 12).map((category) => (
                <button
                  key={category}
                  onClick={() => { setCategoryFilter(category); setSubcategoryFilter("All"); setView("browse"); setSelected(null); }}
                  className="hover:underline shrink-0"
                  style={{ fontWeight: categoryFilter === category ? 700 : 400 }}
                >
                  {category}
                </button>
              ))}
            </div>
          </div>
        </header>
      )}

      {notifPanelOpen && currentUser && (
        <div
          className="fixed inset-0 z-30"
          onClick={() => setNotifPanelOpen(false)}
        >
          <div
            className="absolute right-4 top-16 w-80 max-h-96 overflow-y-auto bg-white rounded-2xl shadow-xl border"
            style={{ borderColor: "#DDD8CC" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: "#EFEBE0" }}>
              <h3 className="text-sm font-semibold" style={{ color: INK }}>
                Notifications
              </h3>
              {notifications.some((n) => !n.read) && (
                <button
                  onClick={markNotificationsRead}
                  className="text-xs font-medium underline"
                  style={{ color: SLATE }}
                >
                  Mark all read
                </button>
              )}
            </div>
            {notifications.length === 0 ? (
              <p className="text-sm p-4" style={{ color: SLATE }}>
                No notifications yet.
              </p>
            ) : (
              <div>
                {notifications.map((n) => (
                  <button
                    key={n.id}
                    onClick={() => !n.read && markNotificationRead(n.id)}
                    className="w-full text-left p-3 border-b text-sm"
                    style={{
                      borderColor: "#EFEBE0",
                      backgroundColor: n.read ? "white" : "#FBF0DC",
                      color: INK,
                    }}
                  >
                    <div>{n.message}</div>
                    <div className="text-xs mt-1" style={{ color: SLATE }}>
                      {new Date(n.createdAt).toLocaleString()}
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {toast && (
        <div
          className="fixed top-4 right-4 z-30 px-4 py-2 rounded-lg shadow-lg text-sm font-medium text-white"
          style={{ backgroundColor: INK }}
        >
          {toast}
        </div>
      )}

      <main className="max-w-6xl mx-auto px-4 py-8">
        {content.banners
          .filter((b) => b.isActive)
          .map((b) =>
            b.mediaType === "image" && b.imageUrl ? (
              <div
                key={b.id}
                className="mb-4 rounded-lg overflow-hidden border"
                style={{ borderColor: "#DDD8CC" }}
              >
                <img src={b.imageUrl} alt="" className="w-full max-h-56 object-cover" />
                <div
                  className="px-4 py-3 text-sm font-medium"
                  style={{
                    backgroundColor:
                      b.tone === "alert" ? "#F9E4E2" : b.tone === "success" ? "#E7EFE8" : "#E3EDF4",
                    color: b.tone === "alert" ? BERRY : b.tone === "success" ? SAGE : "#3B6E8F",
                  }}
                >
                  {b.message}
                </div>
              </div>
            ) : b.mediaType === "video" && b.videoUrl ? (
              <div
                key={b.id}
                className="mb-4 rounded-lg overflow-hidden border"
                style={{ borderColor: "#DDD8CC" }}
              >
                <video src={b.videoUrl} controls className="w-full max-h-56 bg-black" />
                <div
                  className="px-4 py-3 text-sm font-medium"
                  style={{
                    backgroundColor:
                      b.tone === "alert" ? "#F9E4E2" : b.tone === "success" ? "#E7EFE8" : "#E3EDF4",
                    color: b.tone === "alert" ? BERRY : b.tone === "success" ? SAGE : "#3B6E8F",
                  }}
                >
                  {b.message}
                </div>
              </div>
            ) : (
              <div
                key={b.id}
                className="mb-4 px-4 py-3 rounded-lg text-sm font-medium"
                style={{
                  backgroundColor:
                    b.tone === "alert" ? "#F9E4E2" : b.tone === "success" ? "#E7EFE8" : "#E3EDF4",
                  color: b.tone === "alert" ? BERRY : b.tone === "success" ? SAGE : "#3B6E8F",
                }}
              >
                {b.message}
              </div>
            )
          )}
        {view === "categories" && (
          <section className="max-w-6xl mx-auto">
            <div className="mb-8">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] mb-2" style={{ color: MARIGOLD }}>Shop Stallyard</p>
              <h1 className="text-3xl sm:text-4xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Categories</h1>
              <p className="mt-2 text-sm max-w-2xl" style={{ color: SLATE }}>Browse by main category, then choose a subcategory to see active listings across Stallyard.</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
              {CATEGORIES.map((category) => (
                <div key={category} className="rounded-2xl border bg-white p-5" style={{ borderColor: "#DDD8CC" }}>
                  <button
                    type="button"
                    onClick={() => { setCategoryFilter(category); setSubcategoryFilter("All"); setSearch(""); setView("browse"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                    className="w-full flex items-center gap-3 text-left group"
                  >
                    <span className="w-11 h-11 rounded-full flex items-center justify-center text-xl shrink-0" style={{ backgroundColor: "#F5F1E8" }} aria-hidden="true">{CATEGORY_ICON[category] || "📦"}</span>
                    <span className="font-semibold text-lg group-hover:underline" style={{ color: INK }}>{category}</span>
                  </button>
                  <div className="mt-4 flex flex-wrap gap-x-3 gap-y-2">
                    {(SUBCATEGORIES[category] || []).map((subcategory) => (
                      <button
                        key={subcategory}
                        type="button"
                        onClick={() => {
                          setCategoryFilter(category);
                          setSubcategoryFilter(subcategory);
                          setSearch("");
                          setSelected(null);
                          setView("browse");
                          window.scrollTo({ top: 0, behavior: "smooth" });
                        }}
                        className="text-sm text-left hover:underline"
                        style={{ color: SLATE }}
                      >
                        {subcategory}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {view === "how-it-works" && (
          <section className="max-w-5xl mx-auto">
            <div className="text-center mb-10">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] mb-2" style={{ color: MARIGOLD }}>Simple. Secure. Built for Nigeria.</p>
              <h1 className="text-3xl sm:text-5xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>How Stallyard works</h1>
              <p className="mt-4 text-sm sm:text-base max-w-2xl mx-auto leading-7" style={{ color: SLATE }}>Buy and sell across Nigeria with secure Paystack payments, a buyer delivery token, and proof of delivery before seller funds are released.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-10">
              {[
                { number: "1", title: "Find an item", text: "Browse active Stallyard listings, search by keyword, or shop by category and subcategory." },
                { number: "2", title: "Pay securely", text: "Complete checkout in Nigerian naira through Paystack. Stallyard does not support cash on delivery." },
                { number: "3", title: "Receive and inspect your order", text: "Your private 10-digit delivery token is visible in your order details immediately after payment. Keep it private until you receive and inspect the item." },
                { number: "4", title: "Share the token at handoff", text: "Give the token to the seller only after you accept the item. The seller uploads delivery proof and enters the token. If there is no active dispute or return, the seller payment is released." },
              ].map((step) => (
                <div key={step.number} className="rounded-2xl border bg-white p-6 sm:p-7" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-start gap-4">
                    <div className="w-11 h-11 rounded-full flex items-center justify-center shrink-0 font-bold text-lg" style={{ backgroundColor: MARIGOLD, color: INK }}>{step.number}</div>
                    <div>
                      <h2 className="text-xl font-semibold mb-2" style={{ color: INK }}>{step.title}</h2>
                      <p className="text-sm leading-6" style={{ color: SLATE }}>{step.text}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-2xl border p-6 sm:p-8 mb-8" style={{ borderColor: "#DDD8CC", backgroundColor: "#FFF9EE" }}>
              <h2 className="text-2xl font-semibold mb-5" style={{ color: INK }}>Important things to know</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4 text-sm leading-6" style={{ color: SLATE }}>
                <div className="flex gap-3"><span aria-hidden="true">🇳🇬</span><span><strong style={{ color: INK }}>Nigeria only:</strong> Stallyard is for buyers and sellers in Nigeria and marketplace payments are in naira.</span></div>
                <div className="flex gap-3"><span aria-hidden="true">✓</span><span><strong style={{ color: INK }}>Verified sellers:</strong> sellers must complete Stallyard verification before they can list items.</span></div>
                <div className="flex gap-3"><span aria-hidden="true">🔒</span><span><strong style={{ color: INK }}>No cash on delivery:</strong> payments are processed electronically through Paystack.</span></div>
                <div className="flex gap-3"><span aria-hidden="true">⚖️</span><span><strong style={{ color: INK }}>Disputes and returns:</strong> an active dispute or return blocks seller payment release while the issue is reviewed.</span></div>
              </div>
            </div>

            <div className="rounded-2xl p-7 sm:p-9 text-center" style={{ backgroundColor: INK }}>
              <h2 className="text-2xl sm:text-3xl font-semibold text-white">Ready to use Stallyard?</h2>
              <p className="mt-2 text-sm" style={{ color: "#C9CCD3" }}>Browse active listings or create an account to get started.</p>
              <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
                <button
                  type="button"
                  onClick={() => { setCategoryFilter("All"); setSubcategoryFilter("All"); setSearch(""); setSelected(null); setView("browse"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-lg font-semibold"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Browse listings
                </button>
                {!currentUser && (
                  <button
                    type="button"
                    onClick={() => { setSelected(null); setView("create-account"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                    className="w-full sm:w-auto px-5 py-2.5 rounded-lg border font-semibold"
                    style={{ borderColor: "#667085", color: "#FFFFFF" }}
                  >
                    Create an account
                  </button>
                )}
              </div>
            </div>
          </section>
        )}

        {view === "create-account" && (
          <section className="max-w-6xl mx-auto">
            <div className="text-center mb-10">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] mb-2" style={{ color: MARIGOLD }}>Join Stallyard</p>
              <h1 className="text-3xl sm:text-5xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Create your Stallyard account</h1>
              <p className="mt-4 text-sm sm:text-base max-w-2xl mx-auto leading-7" style={{ color: SLATE }}>Choose the account path that fits what you want to do. Stallyard is a Nigeria-only marketplace and marketplace payments are in naira.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-10">
              {[
                {
                  intent: "buyer",
                  icon: "🛍️",
                  title: "Create a buyer account",
                  text: "Shop active listings, save items, place orders, and receive your private delivery token immediately after successful payment.",
                  button: "Create buyer account",
                },
                {
                  intent: "seller",
                  icon: "🏷️",
                  title: "Create a seller account",
                  text: "Create a personal account, complete seller verification, then list products and receive payouts after valid delivery confirmation.",
                  button: "Create seller account",
                },
              ].map((option) => (
                <div key={option.intent} className="rounded-2xl border bg-white p-6 flex flex-col" style={{ borderColor: "#DDD8CC" }}>
                  <div className="w-12 h-12 rounded-full flex items-center justify-center text-2xl mb-4" style={{ backgroundColor: "#FFF4D8" }} aria-hidden="true">{option.icon}</div>
                  <h2 className="text-xl font-semibold mb-2" style={{ color: INK }}>{option.title}</h2>
                  <p className="text-sm leading-6 mb-6 flex-1" style={{ color: SLATE }}>{option.text}</p>
                  <button
                    type="button"
                    onClick={() => openRegistration(option.intent)}
                    className="w-full px-4 py-2.5 rounded-lg font-semibold text-sm"
                    style={{ backgroundColor: MARIGOLD, color: INK }}
                  >
                    {option.button}
                  </button>
                </div>
              ))}
            </div>

            <div className="rounded-2xl border bg-white overflow-hidden" style={{ borderColor: "#DDD8CC" }}>
              <div className="p-6 sm:p-8 border-b" style={{ borderColor: "#EEE9DE", backgroundColor: "#FFF9EE" }}>
                <h2 className="text-2xl sm:text-3xl font-semibold" style={{ color: INK }}>What you’ll need to sign up</h2>
                <p className="mt-2 text-sm leading-6 max-w-3xl" style={{ color: SLATE }}>Every Stallyard account can buy and later become a seller. Seller verification is required before listings can go live.</p>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-0">
                <div className="p-6 sm:p-7 lg:border-r" style={{ borderColor: "#EEE9DE" }}>
                  <h3 className="font-semibold text-lg mb-4" style={{ color: INK }}>Buyer account</h3>
                  <ul className="space-y-3 text-sm leading-6" style={{ color: SLATE }}>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Username and a strong password</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Working email address and email verification</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>First and last name</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Nigerian phone number and Nigeria residence details for account/checkout use</span></li>
                  </ul>
                </div>

                <div className="p-6 sm:p-7 lg:border-r" style={{ borderColor: "#EEE9DE" }}>
                  <h3 className="font-semibold text-lg mb-4" style={{ color: INK }}>Seller verification</h3>
                  <ul className="space-y-3 text-sm leading-6" style={{ color: SLATE }}>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Everything needed for a buyer account</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Valid government-issued ID</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Verified phone number and Nigerian address/profile details</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>One bank statement to support seller verification and account-tenure review</span></li>
                    <li className="flex gap-2"><span style={{ color: SAGE }}>✓</span><span>Seller approval is required before publishing listings</span></li>
                  </ul>
                </div>

              </div>
            </div>

            <div className="mt-8 rounded-2xl p-6 sm:p-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4" style={{ backgroundColor: INK }}>
              <div>
                <h2 className="text-xl sm:text-2xl font-semibold text-white">Already have a Stallyard account?</h2>
                <p className="mt-1 text-sm" style={{ color: "#C9CCD3" }}>Sign in and continue where you left off.</p>
              </div>
              <button
                type="button"
                onClick={() => { setAuthMode("login"); setAuthError(""); setAuthReturnView("browse"); setView("signin"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                className="px-5 py-2.5 rounded-lg font-semibold shrink-0"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                Sign in
              </button>
            </div>
          </section>
        )}

        {view === "browse" && (
          <>
            {isHomeState && (
              <div className="mb-8 relative left-1/2 -translate-x-1/2 w-[calc(100vw-2rem)] sm:w-[calc(100vw-4rem)] max-w-[1600px]">
                {(() => {
                  const slides = homepageAds.filter((ad) => ad.imageUrl);
                  if (!slides.length) return null;
                  const activeIndex = Math.min(homepageHeroSlide, slides.length - 1);
                  const ad = slides[activeIndex];
                  const hero = (
                    <picture>
                      {ad.posterUrl && <source media="(max-width: 639px)" srcSet={ad.posterUrl} />}
                      <img
                        src={ad.imageUrl}
                        alt={`Stallyard featured promotion ${activeIndex + 1}`}
                        width="1600"
                        height="400"
                        loading={activeIndex === 0 ? "eager" : "lazy"}
                        fetchPriority={activeIndex === 0 ? "high" : "auto"}
                        decoding="async"
                        className="absolute inset-0 w-full h-full object-cover"
                      />
                    </picture>
                  );
                  return (
                    <section
                      className="relative overflow-hidden rounded-2xl border bg-white w-full aspect-square sm:aspect-[4/1]"
                      style={{ borderColor: "#DDD8CC" }}
                      aria-label="Featured Stallyard promotions"
                    >
                      {ad.linkUrl ? (
                        <a href={ad.linkUrl} className="absolute inset-0 block" aria-label={`Open promotion ${activeIndex + 1}`}>
                          {hero}
                        </a>
                      ) : hero}

                      {slides.length > 1 && (
                        <>
                          <div className="absolute bottom-3 left-1/2 -translate-x-1/2 z-10 flex items-center gap-2 rounded-full bg-black/55 px-3 py-2">
                            {slides.map((slide, index) => (
                              <button
                                key={slide.slot}
                                type="button"
                                onClick={() => setHomepageHeroSlide(index)}
                                aria-label={`Show promotion ${index + 1}`}
                                aria-current={index === activeIndex ? "true" : undefined}
                                className="h-2.5 w-2.5 rounded-full border border-white"
                                style={{ backgroundColor: index === activeIndex ? "white" : "transparent" }}
                              />
                            ))}
                          </div>
                          <div className="absolute bottom-3 right-3 z-10 flex gap-2">
                            <button
                              type="button"
                              onClick={() => setHomepageHeroSlide((activeIndex - 1 + slides.length) % slides.length)}
                              aria-label="Previous promotion"
                              className="h-9 w-9 rounded-full bg-white border shadow flex items-center justify-center text-xl"
                              style={{ borderColor: "#DDD8CC", color: INK }}
                            >
                              ‹
                            </button>
                            <button
                              type="button"
                              onClick={() => setHomepageHeroSlide((activeIndex + 1) % slides.length)}
                              aria-label="Next promotion"
                              className="h-9 w-9 rounded-full bg-white border shadow flex items-center justify-center text-xl"
                              style={{ borderColor: "#DDD8CC", color: INK }}
                            >
                              ›
                            </button>
                            <button
                              type="button"
                              onClick={() => setHomepageHeroPaused((paused) => !paused)}
                              aria-label={homepageHeroPaused ? "Play promotions" : "Pause promotions"}
                              className="h-9 w-9 rounded-full bg-white border shadow flex items-center justify-center text-sm font-bold"
                              style={{ borderColor: "#DDD8CC", color: INK }}
                            >
                              {homepageHeroPaused ? "▶" : "Ⅱ"}
                            </button>
                          </div>
                        </>
                      )}
                    </section>
                  );
                })()}
              </div>
            )}

            {categoryFilter !== "All" && (
              <div className="mb-6 flex items-center justify-between gap-3 rounded-xl border bg-white px-4 py-3" style={{ borderColor: "#DDD8CC" }}>
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-2xl" aria-hidden="true">{CATEGORY_ICON[categoryFilter] || "📦"}</span>
                  <div className="min-w-0">
                    <p className="text-xs" style={{ color: SLATE }}>Browsing category</p>
                    <p className="font-semibold truncate" style={{ color: INK }}>{categoryFilter}</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setCategoryFilter("All")}
                  className="text-sm font-medium underline shrink-0"
                  style={{ color: SLATE }}
                >
                  View all
                </button>
              </div>
            )}

            {isHomeState && featuredPicks.length > 0 && (
              <div className="mb-10">
                <h3 className="text-xl mb-4" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                  Featured picks
                </h3>
                <div className="flex gap-5 overflow-x-auto pb-2 -mx-1 px-1">
                  {featuredPicks.map((l) => (
                    <div key={l.id} className="shrink-0" style={{ width: "260px" }}>
                      <PriceTagCard
                        listing={l}
                        rating={getListingRating(l.id)}
                        isSaved={watchlist.includes(l.id)}
                        onToggleWatchlist={toggleWatchlist}
                        onOpenStorefront={openStorefront}
                        now={nowTick}
                        onVacation={getSellerVacationInfo(l.ownerUsername)}
                        onOpen={(listing) => {
                          setActiveImg(0);
                          setSelected(listing);
                        }}
                        onAddToCart={addToCart}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {isHomeState && newArrivals.length > 0 && (
              <div className="mb-10">
                <h3 className="text-xl mb-4" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                  New arrivals
                </h3>
                <div className="flex gap-5 overflow-x-auto pb-2 -mx-1 px-1">
                  {newArrivals.map((l) => (
                    <div key={l.id} className="shrink-0" style={{ width: "260px" }}>
                      <PriceTagCard
                        listing={l}
                        rating={getListingRating(l.id)}
                        isSaved={watchlist.includes(l.id)}
                        onToggleWatchlist={toggleWatchlist}
                        onOpenStorefront={openStorefront}
                        now={nowTick}
                        onVacation={getSellerVacationInfo(l.ownerUsername)}
                        onOpen={(listing) => {
                          setActiveImg(0);
                          setSelected(listing);
                        }}
                        onAddToCart={addToCart}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            <h3 className="text-xl mb-4" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              {isHomeState ? "Shop all" : "Results"}
            </h3>

            <div className="flex flex-col sm:flex-row gap-3 mb-5">
              <div className="relative flex-1">
                <Search
                  size={18}
                  className="absolute left-3 top-1/2 -translate-y-1/2"
                  style={{ color: SLATE }}
                />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search the stalls..."
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg border outline-none focus:ring-2"
                  style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}
                />
              </div>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="px-3 py-2.5 rounded-lg border outline-none bg-white text-sm"
                style={{ borderColor: "#DDD8CC", color: INK }}
              >
                <option value="featured">Featured</option>
                <option value="newest">Newest</option>
                <option value="price-asc">Price: Low to High</option>
                <option value="price-desc">Price: High to Low</option>
                <option value="rating">Top Rated</option>
              </select>
              <button
                onClick={() => setFiltersOpen((f) => !f)}
                className="px-3 py-2.5 rounded-lg border text-sm font-medium whitespace-nowrap"
                style={{
                  borderColor: filtersOpen ? INK : "#DDD8CC",
                  backgroundColor: filtersOpen ? INK : "white",
                  color: filtersOpen ? "white" : SLATE,
                }}
              >
                Filters{(priceMin || priceMax || conditionFilter !== "All") ? " •" : ""}
              </button>
            </div>

            {filtersOpen && (
              <div className="flex flex-wrap items-end gap-4 mb-5 p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                <div>
                  <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                    Min price
                  </label>
                  <input
                    type="number"
                    min="0"
                    value={priceMin}
                    onChange={(e) => setPriceMin(e.target.value)}
                    placeholder="₦0"
                    className="w-24 px-2 py-1.5 rounded-lg border outline-none text-sm"
                    style={{ borderColor: "#DDD8CC" }}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                    Max price
                  </label>
                  <input
                    type="number"
                    min="0"
                    value={priceMax}
                    onChange={(e) => setPriceMax(e.target.value)}
                    placeholder="Any"
                    className="w-24 px-2 py-1.5 rounded-lg border outline-none text-sm"
                    style={{ borderColor: "#DDD8CC" }}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                    Condition
                  </label>
                  <select
                    value={conditionFilter}
                    onChange={(e) => setConditionFilter(e.target.value)}
                    className="px-2 py-1.5 rounded-lg border outline-none text-sm bg-white"
                    style={{ borderColor: "#DDD8CC" }}
                  >
                    <option value="All">All</option>
                    {CONDITIONS.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
                {(priceMin || priceMax || conditionFilter !== "All") && (
                  <button
                    onClick={() => {
                      setPriceMin("");
                      setPriceMax("");
                      setConditionFilter("All");
                    }}
                    className="text-xs font-medium underline"
                    style={{ color: SLATE }}
                  >
                    Clear filters
                  </button>
                )}
              </div>
            )}

            {categoryFilter !== "All" && (SUBCATEGORIES[categoryFilter] || []).length > 0 && (
              <div className="mb-4">
                <label className="block text-xs font-semibold mb-1" style={{ color: SLATE }}>Subcategory</label>
                <select
                  value={subcategoryFilter}
                  onChange={(e) => setSubcategoryFilter(e.target.value)}
                  className="w-full sm:w-auto px-3 py-2 rounded-lg border bg-white text-sm"
                  style={{ borderColor: "#DDD8CC", color: INK }}
                >
                  <option value="All">All {categoryFilter}</option>
                  {(SUBCATEGORIES[categoryFilter] || []).map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            )}
            {categoryFilter !== "All" && (
              <button
                onClick={() => setCategoryFilter("All")}
                className="mb-6 text-xs font-medium underline"
                style={{ color: SLATE }}
              >
                ← Clear category ({categoryFilter})
              </button>
            )}

            {loaded && filtered.length === 0 && (
              <div className="text-center py-20">
                <PackageOpen size={40} className="mx-auto mb-3" style={{ color: SLATE }} />
                <p className="text-lg" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                  No stalls open in this aisle yet.
                </p>
                <p className="text-sm mt-1" style={{ color: SLATE }}>
                  Be the first to set one up.
                </p>
                {!currentMember?.isAdmin && <button
                  onClick={() => setView("sell")}
                  className="mt-4 px-4 py-2 rounded-lg font-medium text-sm"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  List something
                </button>}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6">
              {filtered.map((l) => (
                <PriceTagCard
                  key={l.id}
                  listing={l}
                  rating={getListingRating(l.id)}
                  isSaved={watchlist.includes(l.id)}
                  onToggleWatchlist={toggleWatchlist}
                  onOpenStorefront={openStorefront}
                  now={nowTick}
                  onVacation={getSellerVacationInfo(l.ownerUsername)}
                  onOpen={(listing) => {
                    setActiveImg(0);
                    setSelected(listing);
                  }}
                  onAddToCart={addToCart}
                />
              ))}
            </div>
          </>
        )}

        {view === "shipping-delivery" && (
          <section className="max-w-6xl mx-auto">
            <div className="text-center mb-10">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] mb-2" style={{ color: MARIGOLD }}>Shipping & delivery</p>
              <h1 className="text-3xl sm:text-5xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>From seller to buyer, safely</h1>
              <p className="mt-4 text-sm sm:text-base max-w-3xl mx-auto leading-7" style={{ color: SLATE }}>
                Stallyard is a Nigeria-only marketplace. Sellers arrange delivery, buyers track their order in Stallyard, and the buyer can see a private 10-digit delivery token immediately after successful payment.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-10">
              {[
                { number: "1", title: "Seller prepares the order", text: "After a paid order appears, the seller prepares the item for delivery and adds carrier or tracking information when available." },
                { number: "2", title: "Get your private token", text: "Your 10-digit delivery token appears in your order details immediately after successful payment. Keep it private while the item is in transit." },
                { number: "3", title: "Receive and inspect", text: "Inspect the item carefully at delivery. Give the token to the seller only when you have received the correct item and are satisfied." },
                { number: "4", title: "Seller completes delivery", text: "The seller uploads the delivery photo and enters the buyer's token. If the token is valid and there is no active dispute or return, the seller payment can be released immediately." },
              ].map((step) => (
                <div key={step.number} className="rounded-2xl border bg-white p-6 sm:p-7" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-start gap-4">
                    <div className="w-11 h-11 rounded-full flex items-center justify-center shrink-0 font-bold text-lg" style={{ backgroundColor: MARIGOLD, color: INK }}>{step.number}</div>
                    <div>
                      <h2 className="text-xl font-semibold mb-2" style={{ color: INK }}>{step.title}</h2>
                      <p className="text-sm leading-6" style={{ color: SLATE }}>{step.text}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
              <div className="rounded-2xl border bg-white p-6 sm:p-8" style={{ borderColor: "#DDD8CC" }}>
                <h2 className="text-2xl font-semibold mb-5" style={{ color: INK }}>For buyers</h2>
                <ul className="space-y-3 text-sm leading-6" style={{ color: SLATE }}>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Track your order status in Stallyard. Keep your 10-digit delivery token private. Release it to the seller only when you have received the item, inspected it, and are fully satisfied with your order.</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Inspect the delivered item before handing the token to the seller.</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Use your Stallyard order page to follow order and delivery status.</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>If an item is late, missing, damaged, or significantly not as described, use Stallyard's support/dispute process instead of giving the token early.</span></li>
                </ul>
              </div>

              <div className="rounded-2xl border bg-white p-6 sm:p-8" style={{ borderColor: "#DDD8CC" }}>
                <h2 className="text-2xl font-semibold mb-5" style={{ color: INK }}>For sellers</h2>
                <ul className="space-y-3 text-sm leading-6" style={{ color: SLATE }}>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Package the item securely and keep delivery/tracking information accurate when available.</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Never ask the buyer for a delivery token before the buyer has received, inspected, and accepted the item.</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Enter the token only at delivery and upload a clear delivery photo as proof.</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Do not mark an item delivered before actual delivery. An active dispute or return keeps the payment locked.</span></li>
                </ul>
              </div>
            </div>

            <div className="rounded-2xl border p-6 sm:p-8 mb-8" style={{ borderColor: "#E7C8C5", backgroundColor: "#FFF7F6" }}>
              <h2 className="text-2xl font-semibold mb-4" style={{ color: INK }}>If something goes wrong</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm leading-6" style={{ color: SLATE }}>
                <div><strong style={{ color: INK }}>Late or missing delivery:</strong> check the order status and tracking information first, then contact support if the delivery cannot be resolved.</div>
                <div><strong style={{ color: INK }}>Damaged or wrong item:</strong> do not give the delivery token simply to complete the transaction. Use the return/dispute process where applicable.</div>
                <div><strong style={{ color: INK }}>Active dispute or return:</strong> seller payment remains locked while the case is being reviewed.</div>
                <div><strong style={{ color: INK }}>No cash on delivery:</strong> marketplace payments are processed electronically through Paystack.</div>
              </div>
            </div>

            <div className="rounded-2xl p-7 sm:p-9 text-center" style={{ backgroundColor: INK }}>
              <h2 className="text-2xl sm:text-3xl font-semibold text-white">Need to check an order?</h2>
              <p className="mt-2 text-sm" style={{ color: "#C9CCD3" }}>Open your Stallyard orders to review delivery status, or contact support if you need help.</p>
              <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
                <button
                  type="button"
                  onClick={() => {
                    if (!currentUser) {
                      setAuthMode("login");
                      setAuthError("");
                      setAuthReturnView("orders");
                      setView("signin");
                    } else {
                      setView("orders");
                    }
                    window.scrollTo({ top: 0, behavior: "smooth" });
                  }}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-lg font-semibold"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Track your orders
                </button>
                <button
                  type="button"
                  onClick={() => { setView("help"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-lg border font-semibold"
                  style={{ borderColor: "#667085", color: "#FFFFFF" }}
                >
                  Contact support
                </button>
              </div>
            </div>
          </section>
        )}

        {view === "become-seller" && (
          <section className="max-w-6xl mx-auto">
            <div className="text-center mb-10">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] mb-2" style={{ color: MARIGOLD }}>Sell on Stallyard</p>
              <h1 className="text-3xl sm:text-5xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Become a Stallyard seller</h1>
              <p className="mt-4 text-sm sm:text-base max-w-3xl mx-auto leading-7" style={{ color: SLATE }}>
                Reach buyers across Nigeria, list your products, and get paid after a secure delivery handoff. Seller verification is required before any listing can go live.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-10">
              <div className="rounded-2xl border bg-white p-6" style={{ borderColor: "#DDD8CC" }}>
                <div className="w-11 h-11 rounded-full flex items-center justify-center text-xl mb-4" style={{ backgroundColor: "#FFF4D8" }} aria-hidden="true">✓</div>
                <h2 className="text-xl font-semibold mb-2" style={{ color: INK }}>Get verified first</h2>
                <p className="text-sm leading-6" style={{ color: SLATE }}>Stallyard reviews seller information before selling is enabled. This helps protect buyers and the marketplace.</p>
              </div>
              <div className="rounded-2xl border bg-white p-6" style={{ borderColor: "#DDD8CC" }}>
                <div className="w-11 h-11 rounded-full flex items-center justify-center text-xl mb-4" style={{ backgroundColor: "#FFF4D8" }} aria-hidden="true">5%</div>
                <h2 className="text-xl font-semibold mb-2" style={{ color: INK }}>Simple selling fee</h2>
                <p className="text-sm leading-6" style={{ color: SLATE }}>Stallyard charges a 5% commission on completed sales. Marketplace payments are processed in Nigerian naira.</p>
              </div>
              <div className="rounded-2xl border bg-white p-6" style={{ borderColor: "#DDD8CC" }}>
                <div className="w-11 h-11 rounded-full flex items-center justify-center text-xl mb-4" style={{ backgroundColor: "#FFF4D8" }} aria-hidden="true">₦</div>
                <h2 className="text-xl font-semibold mb-2" style={{ color: INK }}>Get paid after delivery</h2>
                <p className="text-sm leading-6" style={{ color: SLATE }}>The buyer receives a private 10-digit token immediately after payment. After the buyer receives, inspects, and accepts the item, they give you that token; you upload delivery proof and enter the token. If there is no active dispute or return, your payment can be released.</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
              <div className="rounded-2xl border bg-white p-6 sm:p-8" style={{ borderColor: "#DDD8CC" }}>
                <h2 className="text-2xl font-semibold mb-5" style={{ color: INK }}>Seller-level requirements</h2>
                <h3 className="font-semibold text-sm mb-2" style={{ color: INK }}>Casual Seller · up to ₦500,000 active</h3>
                <ul className="space-y-2 text-sm leading-6 mb-5" style={{ color: SLATE }}>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Completed profile, verified email and verified Nigerian phone</span></li>
                  <li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Live selfie, selfie holding identification and three camera challenges</span></li>
                </ul>
                <h3 className="font-semibold text-sm mb-2" style={{ color: INK }}>Verified Seller · up to ₦20,000,000 active</h3>
                <ul className="space-y-2 text-sm leading-6" style={{ color: SLATE }}>
                  <li className="flex gap-3"><span style={{ color: MARIGOLD }}>✓</span><span>Approved Casual Seller verification</span></li>
                  <li className="flex gap-3"><span style={{ color: MARIGOLD }}>✓</span><span>Accepted ID type with front and applicable back images</span></li>
                  <li className="flex gap-3"><span style={{ color: MARIGOLD }}>✓</span><span>Recent bank statement, complete Nigerian address and verified payout bank</span></li>
                  <li className="flex gap-3"><span style={{ color: MARIGOLD }}>✓</span><span>Administrative approval</span></li>
                </ul>
                <h3 className="font-semibold text-sm mt-5 mb-2" style={{ color: INK }}>Premium Seller · above ₦20,000,000 active</h3>
                <ul className="space-y-2 text-sm leading-6" style={{ color: SLATE }}><li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Approved Verified Seller account and verified payout bank</span></li><li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Recent supporting document and requested listing limit</span></li><li className="flex gap-3"><span style={{ color: SAGE }}>✓</span><span>Manual review and an individually approved numeric limit</span></li></ul>
              </div>

              <div className="rounded-2xl border p-6 sm:p-8" style={{ borderColor: "#DDD8CC", backgroundColor: "#FFF9EE" }}>
                <h2 className="text-2xl font-semibold mb-5" style={{ color: INK }}>How selling works</h2>
                <ol className="space-y-4 text-sm leading-6" style={{ color: SLATE }}>
                  <li className="flex gap-3"><span className="font-bold" style={{ color: INK }}>1.</span><span>Create your Stallyard account and submit seller verification.</span></li>
                  <li className="flex gap-3"><span className="font-bold" style={{ color: INK }}>2.</span><span>After approval, create your listing with photos, price, category and subcategory.</span></li>
                  <li className="flex gap-3"><span className="font-bold" style={{ color: INK }}>3.</span><span>The buyer pays electronically through Paystack. Stallyard does not use cash on delivery.</span></li>
                  <li className="flex gap-3"><span className="font-bold" style={{ color: INK }}>4.</span><span>Deliver the item. After the buyer receives, inspects, and accepts it, collect the token, upload the delivery photo, and enter the buyer’s delivery token.</span></li>
                  <li className="flex gap-3"><span className="font-bold" style={{ color: INK }}>5.</span><span>If the delivery checks pass and there is no active dispute or return, the seller payment is released.</span></li>
                </ol>
              </div>
            </div>

            <div className="rounded-2xl p-7 sm:p-9 text-center" style={{ backgroundColor: INK }}>
              <h2 className="text-2xl sm:text-3xl font-semibold text-white">Ready to start selling?</h2>
              <p className="mt-2 text-sm max-w-2xl mx-auto" style={{ color: "#C9CCD3" }}>
                Seller verification must be approved before your first listing can go live.
              </p>
              <button
                type="button"
                onClick={() => {
                  if (!currentUser) {
                    openRegistration("seller");
                    return;
                  }
                  setSelected(null);
                  setView("sell");
                  window.scrollTo({ top: 0, behavior: "smooth" });
                }}
                className="mt-6 px-6 py-3 rounded-lg font-semibold"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                {currentUser ? (hasSellerListingAccess ? "Create a listing" : "Start seller verification") : "Start seller registration"}
              </button>
              <p className="text-xs mt-4" style={{ color: "#8A93A3" }}>Nigeria-only marketplace · Payments in naira · 5% commission on completed sales</p>
            </div>
          </section>
        )}

        {view === "sell" && !currentMember?.isAdmin && (
          <div className="max-w-xl">
            <h2 className="text-2xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              {editingId ? "Edit your listing" : "Set up a listing"}
            </h2>
            <p className="text-sm mb-6" style={{ color: SLATE }}>
              Visible to everyone browsing Stallyard.
            </p>

            {!currentUser ? (
              <div className="mb-6 p-4 rounded-lg border" style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}>
                <p className="text-sm mb-3" style={{ color: INK }}>
                  Register or log in to open your stall.
                </p>
                <button
                  onClick={() => {
                    setAuthMode("register");
                    setAuthError("");
                    setAuthReturnView(view);
                    setView("signup");
                  }}
                  className="px-4 py-2 rounded-lg font-medium text-sm"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Get started
                </button>
              </div>
            ) : (
              <p className="text-sm mb-6" style={{ color: SLATE }}>
                Selling as <strong style={{ color: INK }}>{currentMember.displayName}</strong>
                {currentMember.isVerified && <Tag color={SAGE}>Identity verified</Tag>}
              </p>
            )}

            {currentUser && !hasSellerListingAccess && (
              <div className="mb-6 p-4 rounded-lg border" style={{ borderColor: SAGE, backgroundColor: "#EDF4EE" }}>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div>
                    <p className="font-semibold text-sm" style={{ color: INK }}>Sell as a verified casual seller</p>
                    <p className="text-xs mt-1" style={{ color: SLATE }}>Complete automatic selfie, liveness, and ID checks. Once approved, you can publish up to ₦500,000 in combined active listings.</p>
                  </div>
                  <button
                    onClick={() => setCasualVerificationOpen(true)}
                    disabled={!casualSellerContactReady}
                    title={!casualSellerContactReady ? "Verify both your email and phone number first" : undefined}
                    className="px-4 py-2 rounded-lg font-medium text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ backgroundColor: SAGE, color: "white" }}
                  >
                    {!casualSellerContactReady
                      ? "Verify email and phone first"
                      : casualSellerStatus?.status === "review_required" ? "Retry verification" : "Verify and start selling"}
                  </button>
                </div>
                <div className="mt-3 p-3 rounded-lg border" style={{ borderColor: MARIGOLD, backgroundColor: "#FFF7E7" }}>
                  <p className="text-xs font-semibold" style={{ color: INK }}>
                    Email and phone verification are required
                  </p>
                  <p className="text-xs mt-1" style={{ color: SLATE }}>
                    You must verify both your email address and phone number before you can continue with face verification.
                  </p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    <Tag color={casualSellerStatus?.emailVerified ? SAGE : BERRY}>
                      Email: {casualSellerStatus?.emailVerified ? "Verified" : "Not verified"}
                    </Tag>
                    <Tag color={casualSellerStatus?.phoneVerified ? SAGE : BERRY}>
                      Phone: {casualSellerStatus?.phoneVerified ? "Verified" : "Not verified"}
                    </Tag>
                  </div>
                </div>
                {casualSellerStatus?.application?.decision_reason && <p className="text-xs mt-2" style={{ color: BERRY }}>{casualSellerStatus.application.decision_reason}</p>}
              </div>
            )}

            {currentUser && hasSellerListingAccess && !currentMember?.isApproved && (
              <div className="mb-6 p-3 rounded-lg border" style={{ borderColor: SAGE, backgroundColor: "white" }}>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <p className="text-sm font-medium" style={{ color: INK }}>Casual Seller</p>
                  <Tag color={SAGE}>Verified</Tag>
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  ₦{Number(casualSellerStatus?.currentActiveValue || 0).toLocaleString("en-NG")} active · ₦{Number(casualSellerStatus?.remainingValue ?? 500000).toLocaleString("en-NG")} remaining from your ₦500,000 combined limit
                </p>
                <div className="h-2 rounded-full overflow-hidden mt-2" style={{ backgroundColor: "#E8E5DC" }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      backgroundColor: SAGE,
                      width: `${Math.min(100, Math.max(0, (Number(casualSellerStatus?.currentActiveValue || 0) / 500000) * 100))}%`,
                    }}
                  />
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  Only active listings count. Draft, sold, cancelled, expired and removed listings do not count toward this limit.
                </p>
                {currentMember?.verificationStatus !== "pending" ? (
                  <div className="mt-3 pt-3 border-t" style={{ borderColor: "#DDD8CC" }}>
                    <p className="text-sm font-medium" style={{ color: INK }}>Need more than ₦500,000?</p>
                    <p className="text-xs mt-1" style={{ color: SLATE }}>Upgrade to Verified Seller to maintain up to ₦20,000,000 in combined active listings.</p>
                    <p className="text-xs mt-1 mb-2" style={{ color: SLATE }}>Add one accepted government ID, upload a recent bank statement, keep a complete default Nigerian address and verified payout bank account, then submit for approval.</p>
                    <select value={verifiedSellerIdForm.idType} onChange={(e) => setVerifiedSellerIdForm((form) => ({ ...form, idType: e.target.value }))} className="w-full px-3 py-2 rounded-lg border text-sm bg-white mb-2" style={{ borderColor: "#DDD8CC" }}>
                      <option value="nin">National Identification Number (NIN)</option>
                      <option value="passport">Nigerian International Passport</option>
                      <option value="drivers_license">Nigerian Driver's Licence</option>
                      <option value="voters_card">Permanent Voter's Card (PVC)</option>
                      <option value="cerpac">Residence/Work Permit (CERPAC)</option>
                    </select>
                    <div className="grid grid-cols-2 gap-2 mb-2">
                      <label className="px-3 py-2 rounded-lg border text-xs font-medium cursor-pointer" style={{ borderColor: "#DDD8CC", backgroundColor: "white", color: INK }}>
                        {verifiedSellerIdImages.front ? "✓ ID front attached" : "Upload ID front"}
                        <input type="file" accept="image/*" onChange={(e) => handleVerifiedSellerIdSelect(e, "front")} className="hidden" disabled={uploadingVerifiedSellerId} />
                      </label>
                      <label className="px-3 py-2 rounded-lg border text-xs font-medium cursor-pointer" style={{ borderColor: "#DDD8CC", backgroundColor: "white", color: INK }}>
                        {verifiedSellerIdImages.back ? "✓ ID back attached" : "Upload ID back, if applicable"}
                        <input type="file" accept="image/*" onChange={(e) => handleVerifiedSellerIdSelect(e, "back")} className="hidden" disabled={uploadingVerifiedSellerId} />
                      </label>
                    </div>
                    <label className="inline-block px-3 py-1.5 rounded-lg border text-xs font-medium cursor-pointer" style={{ borderColor: "#DDD8CC", backgroundColor: "white", color: INK }}>
                      {bankStatementDraft ? "✓ Bank statement attached" : "Upload required bank statement"}
                      <input type="file" accept="image/jpeg,.pdf,application/pdf" onChange={handleBankStatementSelect} className="hidden" disabled={uploadingBankStatement} />
                    </label>
                    <label className="flex gap-2 text-xs mt-2" style={{ color: SLATE }}><input type="checkbox" checked={verifiedSellerConsent} onChange={(e) => setVerifiedSellerConsent(e.target.checked)} /><span>I confirm that the application, address, identity and payout-bank information belong to me and may be retained for seller verification and fraud prevention.</span></label>
                    <button onClick={applyToSell} className="mt-2 px-4 py-2 rounded-lg text-sm font-medium" style={{ backgroundColor: MARIGOLD, color: INK }}>Upgrade to Verified Seller</button>
                  </div>
                ) : <p className="text-xs mt-2" style={{ color: MARIGOLD }}>Your verified-seller application is awaiting admin review.</p>}
              </div>
            )}

            {currentUser && currentMember?.isApproved && currentMember?.sellerTier !== "premium" && (
              <div className="mb-6 p-4 rounded-lg border bg-white" style={{ borderColor: MARIGOLD }}>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <p className="text-sm font-semibold" style={{ color: INK }}>Verified Seller</p>
                  <Tag color={MARIGOLD}>Up to ₦20,000,000</Tag>
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  {formatMoney(Number(casualSellerStatus?.currentActiveValue || 0), "NGN")} active · {formatMoney(Math.max(0, 20000000 - Number(casualSellerStatus?.currentActiveValue || 0)), "NGN")} remaining
                </p>
                <div className="h-2 rounded-full overflow-hidden mt-2" style={{ backgroundColor: "#E8E5DC" }}>
                  <div className="h-full rounded-full" style={{ backgroundColor: MARIGOLD, width: `${Math.min(100, Math.max(0, (Number(casualSellerStatus?.currentActiveValue || 0) / 20000000) * 100))}%` }} />
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  Draft, sold, cancelled, expired and removed listings do not count. Premium Seller approval is required above this combined limit.
                </p>
                <div className="mt-4 pt-4 border-t" style={{ borderColor: "#DDD8CC" }}>
                  <p className="text-sm font-semibold" style={{ color: INK }}>Apply for Premium Seller</p>
                  {casualSellerStatus?.premiumApplication?.status === "pending" ? (
                    <div className="mt-2 p-3 rounded-lg border" style={{ borderColor: MARIGOLD, backgroundColor: "#FFF7E7" }}>
                      <p className="text-sm font-semibold" style={{ color: INK }}>Premium application awaiting review</p>
                      <p className="text-xs mt-1" style={{ color: SLATE }}>Reference: {casualSellerStatus.premiumApplication.reference} · Requested limit: {formatMoney(Number(casualSellerStatus.premiumApplication.requested_limit), "NGN")}</p>
                    </div>
                  ) : (<>
                    {casualSellerStatus?.premiumApplication?.status === "rejected" && (
                      <div className="mt-2 mb-3 p-3 rounded-lg border" style={{ borderColor: BERRY, backgroundColor: "#FBEAEA" }}>
                        <p className="text-sm font-semibold" style={{ color: BERRY }}>Previous Premium application was not approved</p>
                        <p className="text-xs mt-1" style={{ color: SLATE }}>{casualSellerStatus.premiumApplication.decision_reason || "Review the requirements and submit a new application when ready."}</p>
                      </div>
                    )}
                    <p className="text-xs mt-1 mb-3" style={{ color: SLATE }}>Request an individually approved active-listing limit above ₦20,000,000. Premium has no preset marketplace ceiling, and every application is reviewed manually.</p>
                    <label className="block text-xs mb-2" style={{ color: SLATE }}>Requested combined limit
                      <input type="number" min="20000001" step="1" value={premiumSellerLimit} onChange={(e) => setPremiumSellerLimit(e.target.value)} className="block w-full mt-1 px-3 py-2 rounded-lg border" />
                    </label>
                    <label className="inline-block px-3 py-2 rounded-lg border text-xs font-medium cursor-pointer" style={{ borderColor: "#DDD8CC", color: INK }}>
                      {bankStatementDraft ? "✓ Supporting document attached" : "Upload recent bank statement or supporting document"}
                      <input type="file" accept="image/jpeg,.pdf,application/pdf" onChange={handleBankStatementSelect} className="hidden" disabled={uploadingBankStatement} />
                    </label>
                    <label className="flex gap-2 text-xs mt-3" style={{ color: SLATE }}><input type="checkbox" checked={premiumSellerConsent} onChange={(e) => setPremiumSellerConsent(e.target.checked)} /><span>I confirm that the requested limit and supporting information are accurate and may be retained for marketplace risk review.</span></label>
                    <button type="button" onClick={applyForPremiumSeller} className="mt-3 px-4 py-2 rounded-lg text-sm font-semibold" style={{ backgroundColor: INK, color: "white" }}>Submit Premium application</button>
                  </>)}
                </div>
              </div>
            )}

            {currentUser && currentMember?.sellerTier === "premium" && (
              <div className="mb-6 p-4 rounded-lg border bg-white" style={{ borderColor: SAGE }}>
                <div className="flex items-center justify-between gap-3 flex-wrap"><p className="text-sm font-semibold" style={{ color: INK }}>Premium Seller</p><Tag color={SAGE}>{formatMoney(currentMember.sellerListingLimit, "NGN")} approved limit</Tag></div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>{formatMoney(Number(casualSellerStatus?.currentActiveValue || 0), "NGN")} in combined active listings. Only active listings count.</p>
              </div>
            )}

            {currentUser && currentMember?.sellerSuspended && (
              <div className="mb-6 p-4 rounded-lg border" style={{ borderColor: BERRY, backgroundColor: "#FBEAEA" }}><p className="text-sm font-semibold" style={{ color: BERRY }}>Selling access suspended</p><p className="text-xs mt-1" style={{ color: SLATE }}>{currentMember.sellerSuspendedReason || "Contact Stallyard support for review."}</p></div>
            )}

            {currentUser && currentMember?.isApproved === false && currentMember?.verificationStatus === "pending" && (
              <div className="mb-6 p-4 rounded-lg border" style={{ borderColor: MARIGOLD, backgroundColor: "#FBF0DC" }}>
                <p className="text-sm flex items-center gap-2" style={{ color: INK }}>
                  <Tag color={MARIGOLD}>Pending</Tag>
                  Your seller application is under review. You'll be able to publish listings once approved.
                </p>
              </div>
            )}

            {currentUser && currentMember?.isApproved === false && currentMember?.verificationStatus === "rejected" && (
              <div className="mb-6 p-4 rounded-lg border" style={{ borderColor: BERRY, backgroundColor: "#FBEAEA" }}>
                <p className="text-sm mb-1 flex items-center gap-2" style={{ color: INK }}>
                  <Tag color={BERRY}>Rejected</Tag>
                  Your seller application wasn't approved.
                </p>
                {currentMember?.rejectionReason && (
                  <p className="text-xs mb-2" style={{ color: SLATE }}>
                    Reason: {currentMember.rejectionReason}
                  </p>
                )}
                <button
                  onClick={() => setView("sell")}
                  className="px-4 py-2 rounded-lg font-medium text-sm"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Review requirements and re-apply
                </button>
              </div>
            )}

            {currentUser && needsIdVerification && (
              <div className="mb-6 p-4 rounded-lg border" style={{ borderColor: MARIGOLD, backgroundColor: "#FBF0DC" }}>
                <p className="text-sm mb-2" style={{ color: INK }}>
                  Complete seller verification before publishing or editing listings.
                </p>
                <button
                  onClick={() => setIdVerifyOpen(true)}
                  className="px-4 py-2 rounded-lg font-medium text-sm"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Add ID verification
                </button>
              </div>
            )}

            {(!currentUser || (hasSellerListingAccess && !needsIdVerification)) && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Title
                </label>
                <input
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}
                  placeholder="Hand-thrown ceramic mug"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Description
                </label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg border outline-none resize-none"
                  style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}
                  placeholder="Tell buyers what makes it worth a look"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Listing type
                </label>
                <div className="flex gap-2">
                  {[
                    { id: "fixed", label: "Fixed price" },
                    ...(false ? [] : [{ id: "auction", label: "Auction" }]),
                  ].map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      disabled={!!editingId}
                      onClick={() => setForm({ ...form, listingType: opt.id })}
                      className="px-3 py-1.5 rounded-full text-sm font-medium border disabled:opacity-50"
                      style={{
                        borderColor: form.listingType === opt.id ? INK : "#DDD8CC",
                        backgroundColor: form.listingType === opt.id ? INK : "white",
                        color: form.listingType === opt.id ? "white" : SLATE,
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
                {editingId && (
                  <p className="text-xs mt-1" style={{ color: SLATE }}>
                    Listing type can't be changed after publishing.
                  </p>
                )}
              </div>
              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    {form.listingType === "auction" ? "Starting bid" : "Price"}
                  </label>
                  <div className="flex gap-2">
                    <span
                      className="px-2 py-2 rounded-lg border bg-white text-sm flex items-center"
                      style={{ borderColor: "#DDD8CC", color: SLATE }}
                    >
                      {CURRENCIES.NGN.symbol} NGN
                    </span>
                    <input
                      type="number"
                      min="0"
                      step="0.01"
                      value={form.price}
                      onChange={(e) => setForm({ ...form, price: e.target.value })}
                      className="flex-1 px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC", backgroundColor: "white", fontFamily: "'IBM Plex Mono', monospace" }}
                      placeholder="24.00"
                    />
                  </div>
                </div>
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Category
                  </label>
                  <select
                    value={form.category}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        category: e.target.value,
                        subcategory: "",
                        emoji:
                          e.target.value === "Auto Parts" && form.emoji === "📦"
                            ? "🔧"
                            : e.target.value === "Groceries" && form.emoji === "📦"
                            ? "🛒"
                            : form.emoji,
                      })
                    }
                    className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                    style={{ borderColor: "#DDD8CC" }}
                  >
                    {CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Subcategory
                </label>
                <select
                  value={form.subcategory}
                  onChange={(e) => setForm({ ...form, subcategory: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                  style={{ borderColor: "#DDD8CC" }}
                >
                  <option value="">Choose a subcategory</option>
                  {(SUBCATEGORIES[form.category] || []).map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div className="flex gap-3 flex-wrap">
                <div className="flex-1 min-w-[100px]">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Quantity available <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                  </label>
                  <input
                    type="number"
                    min="0"
                    step="1"
                    value={form.quantity}
                    onChange={(e) => setForm({ ...form, quantity: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}
                    placeholder="1"
                  />
                </div>
                <div className="flex-1 min-w-[140px]">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    SKU / part number <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                  </label>
                  <input
                    value={form.sku}
                    onChange={(e) => setForm({ ...form, sku: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}
                    placeholder="e.g. SKU-1024"
                  />
                </div>
                <div className="flex-1 min-w-[140px]">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Brand <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                  </label>
                  <input
                    value={form.brand}
                    onChange={(e) => setForm({ ...form, brand: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}
                    placeholder="e.g. Samsung"
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Shipping fee
                </label>
                <div className="flex items-center gap-2 flex-wrap">
                  <span style={{ color: SLATE }}>{CURRENCIES.NGN.symbol}</span>
                  <input
                    type="number"
                    min="0"
                    step="0.01"
                    value={form.shippingFee}
                    onChange={(e) => setForm({ ...form, shippingFee: e.target.value })}
                    className="w-32 px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC", backgroundColor: "white", fontFamily: "'IBM Plex Mono', monospace" }}
                    placeholder="0.00"
                  />
                  <span className="text-xs" style={{ color: SLATE }}>
                    Leave at 0 for free shipping. Charged once per line, not per quantity.
                  </span>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Condition
                </label>
                <select
                  value={form.condition}
                  onChange={(e) => setForm({ ...form, condition: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                  style={{ borderColor: "#DDD8CC" }}
                >
                  {CONDITIONS.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Location <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                </label>
                <select
                  value={form.state}
                  onChange={(e) => setForm({ ...form, state: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                  style={{ borderColor: "#DDD8CC" }}
                >
                  <option value="">Select state</option>
                  {NIGERIAN_STATES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: INK }}>
                  Shipping options <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                </label>
                <div className="flex flex-wrap gap-3">
                  {SHIPPING_METHODS.map((m) => (
                    <label key={m.value} className="flex items-center gap-2 text-sm" style={{ color: INK }}>
                      <input
                        type="checkbox"
                        checked={form.shippingMethods.includes(m.value)}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            shippingMethods: e.target.checked
                              ? [...form.shippingMethods, m.value]
                              : form.shippingMethods.filter((v) => v !== m.value),
                          })
                        }
                      />
                      {m.label}
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Return policy <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                </label>
                <select
                  value={form.returnPolicy}
                  onChange={(e) => setForm({ ...form, returnPolicy: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                  style={{ borderColor: "#DDD8CC" }}
                >
                  <option value="">Not specified</option>
                  {RETURN_POLICIES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
              {form.listingType === "auction" && (
                <div>
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Auction duration
                  </label>
                  <select
                    value={form.auctionDurationDays}
                    onChange={(e) => setForm({ ...form, auctionDurationDays: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                    style={{ borderColor: "#DDD8CC" }}
                  >
                    <option value="1">1 day</option>
                    <option value="3">3 days</option>
                    <option value="5">5 days</option>
                    <option value="7">7 days</option>
                    <option value="10">10 days</option>
                  </select>
                  {!currentMember?.isAdmin && (
                    <p className="text-xs mt-1" style={{ color: SLATE }}>
                      Auctions always go through admin review before going live.
                    </p>
                  )}
                </div>
              )}
              {form.category === "Auto Parts" && (
                <div className="p-4 rounded-lg border" style={{ borderColor: "#DDD8CC", backgroundColor: "white" }}>
                  <label className="block text-sm font-medium mb-2" style={{ color: INK }}>
                    Fits which vehicle?
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    <input
                      value={form.fitMake}
                      onChange={(e) => setForm({ ...form, fitMake: e.target.value })}
                      placeholder="Make"
                      className="px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <input
                      value={form.fitModel}
                      onChange={(e) => setForm({ ...form, fitModel: e.target.value })}
                      placeholder="Model"
                      className="px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <input
                      value={form.fitYear}
                      onChange={(e) => setForm({ ...form, fitYear: e.target.value })}
                      placeholder="Year(s)"
                      className="px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                  </div>
                  <p className="text-xs mt-2" style={{ color: SLATE }}>
                    e.g. Honda / Civic / 2016–2021
                  </p>
                  <div className="mt-3">
                    <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                      VIN <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                    </label>
                    <input
                      value={form.vin}
                      onChange={(e) => setForm({ ...form, vin: e.target.value })}
                      placeholder="Vehicle identification number"
                      className="w-full px-3 py-2 rounded-lg border outline-none"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                  </div>
                </div>
              )}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: INK }}>
                  Photos ({form.images.length}/{MAX_LISTING_PHOTOS}) {form.images.length < MIN_LISTING_PHOTOS && (
                    <span className="font-normal" style={{ color: BERRY }}>
                      — at least {MIN_LISTING_PHOTOS} required to publish
                    </span>
                  )}
                </label>
                {form.images.length > 0 && (
                  <div className="flex flex-wrap gap-2 mb-2">
                    {form.images.map((src, idx) => (
                      <div
                        key={idx}
                        className="relative w-20 h-20"
                        draggable
                        onDragStart={() => setDraggedPhotoIndex(idx)}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={(e) => {
                          e.preventDefault();
                          if (draggedPhotoIndex !== null && draggedPhotoIndex !== idx) {
                            reorderListingPhotos(draggedPhotoIndex, idx);
                          }
                          setDraggedPhotoIndex(null);
                        }}
                        style={{ cursor: "grab", opacity: draggedPhotoIndex === idx ? 0.4 : 1 }}
                      >
                        <img
                          src={src}
                          alt={`Photo ${idx + 1}`}
                          className="w-full h-full object-cover rounded-lg"
                        />
                        {idx === 0 ? (
                          <span
                            className="absolute bottom-0 left-0 right-0 text-center text-xs py-0.5 rounded-b-lg"
                            style={{ backgroundColor: "rgba(27,36,48,0.75)", color: "white" }}
                          >
                            Main
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => makeListingPhotoMain(idx)}
                            className="absolute bottom-0 left-0 right-0 text-center text-xs py-0.5 rounded-b-lg opacity-0 hover:opacity-100"
                            style={{ backgroundColor: "rgba(27,36,48,0.75)", color: "white" }}
                          >
                            Make main
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => removePhoto(idx)}
                          className="absolute -top-2 -right-2 w-6 h-6 rounded-full flex items-center justify-center"
                          style={{ backgroundColor: BERRY }}
                          aria-label="Remove photo"
                        >
                          <X size={14} color="white" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                {photoUploadProgress.length > 0 && (
                  <div className="mb-2 space-y-1">
                    {photoUploadProgress.map((p, i) => (
                      <div key={i} className="text-xs flex items-center gap-2">
                        <span
                          style={{
                            color: p.status === "error" ? BERRY : p.status === "done" ? "#2F6B3A" : SLATE,
                          }}
                        >
                          {p.status === "uploading" ? "⏳" : p.status === "done" ? "✓" : "✕"} {p.name}
                          {p.message ? ` — ${p.message}` : ""}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                {form.images.length < MAX_LISTING_PHOTOS && (
                  <label
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium cursor-pointer"
                    style={{ borderColor: "#DDD8CC", color: SLATE, backgroundColor: "white" }}
                  >
                    {uploading ? "Uploading..." : "Add photos"}
                    <input
                      type="file"
                      accept="image/jpeg,image/png,image/webp,image/heic,image/heif,image/avif"
                      multiple
                      onChange={handlePhotoSelect}
                      disabled={uploading}
                      className="hidden"
                    />
                  </label>
                )}
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  Up to {MAX_LISTING_PHOTOS} photos, at least {MIN_LISTING_PHOTOS} required. Drag to reorder — the
                  first photo is the cover image buyers see first. Recommended size: {RECOMMENDED_LISTING_PHOTO_DIM}×
                  {RECOMMENDED_LISTING_PHOTO_DIM}px or larger (minimum {MIN_LISTING_PHOTO_DIM}×{MIN_LISTING_PHOTO_DIM}px).
                </p>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  Upload clear photographs of the actual item. Use bright lighting and a clean, neutral background.
                  Show the front, back, sides, manufacturer label, part number, connectors and any damage. Do not
                  upload screenshots, copied internet pictures, phone numbers, watermarks, logos, promotional text
                  or heavily compressed WhatsApp images.
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: INK }}>
                  Icon <span className="font-normal" style={{ color: SLATE }}>(shown if no photos)</span>
                </label>
                <div className="flex flex-wrap gap-2">
                  {EMOJI_CHOICES.map((em) => (
                    <button
                      type="button"
                      key={em}
                      onClick={() => setForm({ ...form, emoji: em })}
                      className="w-10 h-10 rounded-lg text-xl flex items-center justify-center border-2"
                      style={{
                        borderColor: form.emoji === em ? MARIGOLD : "#DDD8CC",
                        backgroundColor: "white",
                      }}
                    >
                      {em}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex gap-3 pt-2 flex-wrap">
                {(!editingId || listings.find((l) => l.id === editingId)?.status === "draft") && (
                  <button
                    type="button"
                    onClick={() => handleSubmit("draft")}
                    className="px-5 py-2.5 rounded-lg font-medium border"
                    style={{ borderColor: "#DDD8CC", color: INK, backgroundColor: "white" }}
                  >
                    Save as draft
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    const isDraftFlow = !editingId || listings.find((l) => l.id === editingId)?.status === "draft";
                    if (isDraftFlow) {
                      if (!form.title.trim()) {
                        showToast("Give it a title first");
                        return;
                      }
                      setPreviewOpen(true);
                    } else {
                      handleSubmit("publish");
                    }
                  }}
                  className="px-5 py-2.5 rounded-lg font-medium"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {editingId && listings.find((l) => l.id === editingId)?.status !== "draft" ? "Save changes" : "Preview"}
                </button>
                {editingId && (
                  <button
                    type="button"
                    onClick={resetForm}
                    className="px-5 py-2.5 rounded-lg font-medium border"
                    style={{ borderColor: "#DDD8CC", color: SLATE }}
                  >
                    Cancel
                  </button>
                )}
              </div>
            </div>
            )}
          </div>
        )}

        {view === "dashboard" && !currentMember?.isAdmin && (
          <div>
            <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
              <div>
                <h2 className="text-2xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                  Seller dashboard
                </h2>
                <p className="text-sm mt-1" style={{ color: SLATE }}>
                  Manage your listings, orders, deliveries, payouts, messages, and seller performance.
                </p>
              </div>
              {currentUser && (
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    onClick={() => setView("wallet")}
                    className="px-3 py-1.5 rounded-lg border text-sm font-medium bg-white"
                    style={{ borderColor: SAGE, color: INK }}
                  >
                    Seller wallet · {formatMoney(walletNetAvailable, "NGN")}
                  </button>
                  {hasSellerListingAccess && (
                    <button
                      onClick={() => {
                        resetForm();
                        setView("sell");
                      }}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      <Plus size={16} />
                      Create a listing
                    </button>
                  )}
                </div>
              )}
            </div>
            {currentUser && (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 my-5">
                {[
                  { label: "Overview", action: () => setRouteField("sellerSection", "overview") },
                  { label: "Listings", action: () => setRouteField("sellerSection", "listings") },
                  { label: "Orders & delivery", action: () => setRouteField("sellerSection", "orders") },
                  { label: "Find drivers", action: () => window.location.assign("/seller/driver-jobs") },
                  { label: "Seller wallet", action: () => setView("wallet") },
                  { label: "Messages", action: () => setView("messages") },
                  { label: "My Stall", action: () => openStorefront(currentUser) },
                ].map((item) => (
                  <button
                    key={item.label}
                    type="button"
                    onClick={item.action}
                    className="px-3 py-2 rounded-lg border text-xs sm:text-sm font-medium bg-white text-left sm:text-center"
                    style={{ borderColor: "#DDD8CC", color: INK }}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            )}
            {currentUser && (
              <section
                className="mb-4 p-4 rounded-xl border"
                style={{ borderColor: MARIGOLD, backgroundColor: "#FFF9EF" }}
                aria-labelledby="seller-delivery-return-responsibility"
              >
                <h3 id="seller-delivery-return-responsibility" className="text-sm font-semibold" style={{ color: INK }}>
                  Seller delivery and return responsibility
                </h3>
                <p className="text-xs mt-1" style={{ color: SLATE }}>
                  You are responsible for the original delivery and return-delivery costs when a return is approved for any of these reasons:
                </p>
                <ol className="mt-2 pl-5 list-decimal space-y-1 text-xs" style={{ color: INK }}>
                  <li>You sent the wrong item.</li>
                  <li>The item is counterfeit.</li>
                  <li>The item is damaged during delivery.</li>
                  <li>The item arrives defective or becomes defective during delivery.</li>
                  <li>The item does not match its listing description or pictures.</li>
                </ol>
                <p className="text-xs mt-2 font-medium" style={{ color: BERRY }}>
                  Describe items accurately, verify their condition, and package them securely before dispatch.
                </p>
              </section>
            )}
            {currentUser && !hasSellerListingAccess && (
              <div className="mb-4 p-4 rounded-lg border flex items-center justify-between gap-3 flex-wrap" style={{ borderColor: SAGE, backgroundColor: "#EDF4EE" }}>
                <div><p className="text-sm font-medium" style={{ color: INK }}>Automatic casual-seller verification</p><p className="text-xs mt-1" style={{ color: SLATE }}>Verify your email and phone first, then complete your live selfie and Nigerian ID check to publish up to ₦500,000 in combined active listings.</p></div>
                <button disabled={!casualSellerContactReady} title={!casualSellerContactReady ? "Verify both your email and phone number first" : undefined} onClick={() => setCasualVerificationOpen(true)} className="px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed" style={{ backgroundColor: SAGE, color: "white" }}>{casualSellerContactReady ? "Start verification" : "Verify email and phone first"}</button>
              </div>
            )}
            {currentUser && hasSellerListingAccess && !currentMember?.isApproved && (
              <div className="mb-4 p-4 rounded-lg border bg-white" style={{ borderColor: SAGE }}>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div>
                    <p className="text-sm font-semibold" style={{ color: INK }}>Casual Seller allowance</p>
                    <p className="text-xs mt-1" style={{ color: SLATE }}>
                      {formatMoney(Number(casualSellerStatus?.currentActiveValue || 0), "NGN")} active · {formatMoney(Number(casualSellerStatus?.remainingValue ?? 500000), "NGN")} remaining
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setView("sell")}
                    className="px-3 py-2 rounded-lg text-sm font-medium"
                    style={{ backgroundColor: MARIGOLD, color: INK }}
                  >
                    Upgrade to Verified Seller
                  </button>
                </div>
                <div className="h-2 rounded-full overflow-hidden mt-3" style={{ backgroundColor: "#E8E5DC" }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      backgroundColor: SAGE,
                      width: `${Math.min(100, Math.max(0, (Number(casualSellerStatus?.currentActiveValue || 0) / 500000) * 100))}%`,
                    }}
                  />
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  ₦500,000 combined active-listing limit. Draft, sold, cancelled, expired and removed listings do not count. Verified Sellers may maintain up to ₦20,000,000.
                </p>
              </div>
            )}
            {currentUser && currentMember?.isApproved && currentMember?.sellerTier !== "premium" && (
              <div className="mb-4 p-4 rounded-lg border bg-white" style={{ borderColor: MARIGOLD }}>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div>
                    <p className="text-sm font-semibold" style={{ color: INK }}>Verified Seller allowance</p>
                    <p className="text-xs mt-1" style={{ color: SLATE }}>
                      {formatMoney(Number(casualSellerStatus?.currentActiveValue || 0), "NGN")} active · {formatMoney(Math.max(0, 20000000 - Number(casualSellerStatus?.currentActiveValue || 0)), "NGN")} remaining
                    </p>
                  </div>
                  <Tag color={MARIGOLD}>Verified Seller</Tag>
                </div>
                <div className="h-2 rounded-full overflow-hidden mt-3" style={{ backgroundColor: "#E8E5DC" }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      backgroundColor: MARIGOLD,
                      width: `${Math.min(100, Math.max(0, (Number(casualSellerStatus?.currentActiveValue || 0) / 20000000) * 100))}%`,
                    }}
                  />
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  ₦20,000,000 combined active-listing limit. Only active listings count. Premium Seller approval is required above ₦20,000,000.
                </p>
              </div>
            )}
            {currentUser && currentMember?.isApproved === false && currentMember?.verificationStatus === "pending" && (
              <div
                className="mb-4 p-4 rounded-lg border"
                style={{ borderColor: MARIGOLD, backgroundColor: "#FBF0DC" }}
              >
                <p className="text-sm flex items-center gap-2" style={{ color: INK }}>
                  <Tag color={MARIGOLD}>Pending</Tag>
                  Your seller application is under review.
                </p>
              </div>
            )}
            {currentUser && currentMember?.isApproved === false && currentMember?.verificationStatus === "rejected" && (
              <div
                className="mb-4 p-4 rounded-lg border flex items-center justify-between gap-3 flex-wrap"
                style={{ borderColor: BERRY, backgroundColor: "#FBEAEA" }}
              >
                <p className="text-sm flex items-center gap-2" style={{ color: INK }}>
                  <Tag color={BERRY}>Rejected</Tag>
                  Your seller application wasn't approved.
                </p>
                <button
                  onClick={() => setView("sell")}
                  className="px-3 py-1.5 rounded-lg text-sm font-medium"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Review requirements and re-apply
                </button>
              </div>
            )}
            {currentUser && needsIdVerification && (
              <div
                className="mb-4 p-4 rounded-lg border flex items-center justify-between gap-3 flex-wrap"
                style={{ borderColor: MARIGOLD, backgroundColor: "#FBF0DC" }}
              >
                <p className="text-sm" style={{ color: INK }}>
                  Complete seller verification before listing items.
                </p>
                <button
                  onClick={() => setIdVerifyOpen(true)}
                  className="px-3 py-1.5 rounded-lg text-sm font-medium"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  Add ID verification
                </button>
              </div>
            )}
            {!currentUser ? (
              <p className="text-sm mt-2" style={{ color: SLATE }}>
                Register or log in from the Sell tab to open your stall.
              </p>
            ) : (
              <>
                {currentMember?.idCountry ? (
                  <p className="text-xs mt-1" style={{ color: SAGE }}>
                    ID on file: {currentMember.idType} ({currentMember.idCountry})
                  </p>
                ) : currentMember?.idVerificationExempt ? (
                  <p className="text-xs mt-1" style={{ color: SLATE }}>
                    ID verification exemption on file
                  </p>
                ) : null}
                <h3 id="seller-overview" className="text-sm font-semibold mb-3 mt-4 scroll-mt-24" style={{ color: INK }}>
                  Overview
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                      {myListings.length}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      active listings
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: SAGE }}>
                      {(() => {
                        // Stallyard is Nigeria-only, so marketplace values are NGN.
                        const byCurrency = {};
                        myListings.forEach((l) => {
                          const cur = l.currency || "NGN";
                          byCurrency[cur] = (byCurrency[cur] || 0) + Number(l.price || 0);
                        });
                        const entries = Object.entries(byCurrency);
                        return entries.length
                          ? entries.map(([cur, amount]) => formatMoney(amount, cur)).join(" + ")
                          : formatMoney(0, "NGN");
                      })()}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      total inventory value
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                      {(() => {
                        // Stallyard is Nigeria-only, so marketplace values are NGN.
                        const byCurrency = {};
                        mySoldItems
                          .filter((i) => i.fulfillmentStatus !== "cancelled")
                          .forEach((i) => {
                            const cur = i.currency || "NGN";
                            byCurrency[cur] = (byCurrency[cur] || 0) + Number(i.price || 0) * (i.qty || 1);
                          });
                        const entries = Object.entries(byCurrency);
                        return entries.length
                          ? entries.map(([cur, amount]) => formatMoney(amount, cur)).join(" + ")
                          : formatMoney(0, "NGN");
                      })()}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      total sales ({mySales.length} order{mySales.length === 1 ? "" : "s"})
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#3B6E8F" }}>
                      {ordersWaitingToShip}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      waiting to ship
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#6B8F71" }}>
                      {ordersInTransit}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      in transit
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#2F6B3A" }}>
                      {completedOrdersCount}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      completed
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: BERRY }}>
                      {activeReturnsDisputes}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      returns/disputes
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                    Seller performance
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{
                          fontFamily: "'IBM Plex Mono', monospace",
                          color: cancellationRate === null || cancellationRate <= 5 ? SAGE : cancellationRate <= 15 ? MARIGOLD : BERRY,
                        }}
                      >
                        {cancellationRate === null ? "—" : `${cancellationRate}%`}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        cancellation rate
                      </div>
                    </div>
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{
                          fontFamily: "'IBM Plex Mono', monospace",
                          color: returnRate === null || returnRate <= 5 ? SAGE : returnRate <= 15 ? MARIGOLD : BERRY,
                        }}
                      >
                        {returnRate === null ? "—" : `${returnRate}%`}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        return rate
                      </div>
                    </div>
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{
                          fontFamily: "'IBM Plex Mono', monospace",
                          color: disputeRate === null || disputeRate === 0 ? SAGE : disputeRate <= 10 ? MARIGOLD : BERRY,
                        }}
                      >
                        {disputeRate === null ? "—" : `${disputeRate}%`}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        dispute rate
                      </div>
                    </div>
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{
                          fontFamily: "'IBM Plex Mono', monospace",
                          color: onTimeShippingRate === null || onTimeShippingRate >= 90 ? SAGE : onTimeShippingRate >= 70 ? MARIGOLD : BERRY,
                        }}
                      >
                        {onTimeShippingRate === null ? "—" : `${onTimeShippingRate}%`}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        on-time shipping
                      </div>
                    </div>
                  </div>
                  <p className="text-xs mt-3" style={{ color: SLATE }}>
                    On-time shipping counts items marked Shipped within 48 hours of the sale.
                  </p>
                </div>

                {myWarnings.length > 0 && (
                  <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: BERRY }}>
                    <h3 className="text-sm font-semibold mb-2 flex items-center gap-2" style={{ color: INK }}>
                      Warnings <Tag color={BERRY}>{myWarnings.length}</Tag>
                    </h3>
                    <div className="space-y-2">
                      {myWarnings.map((w) => (
                        <div key={w.id} className="text-sm p-3 rounded-lg" style={{ backgroundColor: "#FBEAEA", color: INK }}>
                          {w.message}
                          <div className="text-xs mt-1" style={{ color: SLATE }}>
                            {new Date(w.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                    <h3 className="text-sm font-semibold" style={{ color: INK }}>
                      Balance
                    </h3>
                    <button
                      onClick={() => setView("wallet")}
                      className="text-xs font-medium underline"
                      style={{ color: SLATE }}
                    >
                      View full wallet →
                    </button>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: SAGE }}
                      >
                        {formatMoney(walletNetAvailable, "NGN")}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        available
                      </div>
                    </div>
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: MARIGOLD }}
                      >
                        {formatMoney(walletHeld, "NGN")}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        on hold
                      </div>
                    </div>
                    <div>
                      <div
                        className="text-xl font-semibold"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                      >
                        {myWithdrawals.filter((w) => w.status === "processing").length}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        pending requests
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span style={{ color: SLATE }}>₦</span>
                    <input
                      type="number"
                      min="0"
                      max={walletNetAvailable}
                      step="0.01"
                      value={withdrawAmount}
                      onChange={(e) => setWithdrawAmount(e.target.value)}
                      placeholder={walletNetAvailable.toFixed(2)}
                      className="w-28 px-3 py-1.5 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={async () => {
                        await requestWithdrawal(withdrawAmount || walletNetAvailable);
                        setWithdrawAmount("");
                      }}
                      disabled={walletNetAvailable <= 0}
                      className="px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      Request withdrawal
                    </button>
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-2" style={{ color: INK }}>
                    Upcoming payouts
                  </h3>
                  {myWithdrawals.filter((w) => w.status === "processing").length === 0 ? (
                    <p className="text-xs" style={{ color: SLATE }}>
                      No payouts in progress right now.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {myWithdrawals
                        .filter((w) => w.status === "processing")
                        .slice(0, 5)
                        .map((w) => (
                          <div key={w.id} className="flex items-center justify-between text-sm">
                            <span style={{ color: INK }}>
                              {formatMoney(Number(w.amount), "NGN")} to your bank
                            </span>
                            <span className="text-xs" style={{ color: SLATE }}>
                              Requested {new Date(w.requestedAt).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                            </span>
                          </div>
                        ))}
                    </div>
                  )}
                </div>

                <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-sm font-semibold" style={{ color: INK }}>
                      Recent activity
                    </h3>
                    <button
                      onClick={() => setView("orders")}
                      className="text-xs font-medium underline"
                      style={{ color: SLATE }}
                    >
                      View all orders →
                    </button>
                  </div>
                  {myRecentActivity.length === 0 ? (
                    <p className="text-xs" style={{ color: SLATE }}>
                      Nothing to show yet — activity will appear here once you make a sale.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {myRecentActivity.map((n) => (
                        <div key={n.id} className="text-sm" style={{ color: INK }}>
                          {n.message}
                          <span className="text-xs ml-2" style={{ color: SLATE }}>
                            {new Date(n.at).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div>
                      <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: INK }}>
                        🌴 Vacation mode
                        {currentMember?.vacationMode && <Tag color={MARIGOLD}>On</Tag>}
                      </h3>
                      {currentMember?.vacationMode ? (
                        <p className="text-xs mt-1" style={{ color: SLATE }}>
                          Buyers see a notice on your listings
                          {currentMember.vacationReturnDate
                            ? ` that you're back on ${new Date(currentMember.vacationReturnDate).toLocaleDateString(undefined, { month: "short", day: "numeric" })}`
                            : ""}
                          .
                        </p>
                      ) : (
                        <p className="text-xs mt-1" style={{ color: SLATE }}>
                          Let buyers know if you'll be slow to ship.
                        </p>
                      )}
                    </div>
                    {currentMember?.vacationMode ? (
                      <button
                        onClick={endVacation}
                        className="px-3 py-1.5 rounded-lg text-sm font-medium border"
                        style={{ borderColor: "#DDD8CC", color: SLATE }}
                      >
                        Turn off
                      </button>
                    ) : (
                      <button
                        onClick={() => {
                          setVacationForm({ returnDate: "", message: "" });
                          setVacationOpen(true);
                        }}
                        className="px-3 py-1.5 rounded-lg text-sm font-medium"
                        style={{ backgroundColor: MARIGOLD, color: INK }}
                      >
                        Turn on
                      </button>
                    )}
                  </div>
                </div>

                <div id="seller-listings" className="flex items-center gap-2 mb-3 overflow-x-auto scroll-mt-24">
                  {LISTING_MANAGE_TABS.map((t) => {
                    const count =
                      t.key === "all" ? myListings.length : myListings.filter((l) => l.status === t.key).length;
                    if (t.key !== "all" && count === 0) return null;
                    return (
                      <button
                        key={t.key}
                        onClick={() => setRoute((previous) => ({ ...previous, sellerSection: "listings", listingsTab: t.key }))}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium shrink-0"
                        style={{
                          backgroundColor: manageListingsTab === t.key ? INK : "white",
                          color: manageListingsTab === t.key ? "white" : SLATE,
                          border: `1px solid ${manageListingsTab === t.key ? INK : "#DDD8CC"}`,
                        }}
                      >
                        {t.label} ({count})
                      </button>
                    );
                  })}
                </div>

                {myListings.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    Your stall is empty.{" "}
                    <button onClick={() => setView("sell")} className="underline" style={{ color: INK }}>
                      List your first item
                    </button>
                    .
                  </p>
                ) : filteredMyListings.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    Nothing in this tab.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {filteredMyListings.map((l) => (
                      <div
                        key={l.id}
                        className="p-3 rounded-lg border bg-white"
                        style={{ borderColor: "#DDD8CC" }}
                      >
                        <div className="flex items-center justify-between gap-3 flex-wrap">
                          <div className="flex items-center gap-3 min-w-0">
                            <span className="text-2xl">{l.emoji}</span>
                            <div className="min-w-0">
                              <div className="font-medium truncate flex items-center gap-2" style={{ color: INK }}>
                                {l.title}
                                {l.isFeatured && <Tag color={MARIGOLD}>Featured</Tag>}
                                {l.status === "draft" && <Tag color={SLATE}>Draft</Tag>}
                                {l.status === "pending" && <Tag color={MARIGOLD}>Pending review</Tag>}
                                {l.status === "paused" && <Tag color={SLATE}>Paused</Tag>}
                                {l.status === "sold" && <Tag color={BERRY}>Sold out</Tag>}
                                {l.status === "rejected" && <Tag color={BERRY}>Rejected</Tag>}
                                {l.status === "removed" && <Tag color={BERRY}>Taken down</Tag>}
                              </div>
                              <div className="text-xs" style={{ color: SLATE }}>
                                {l.category}
                                {l.condition && l.condition !== "New" ? ` · ${l.condition}` : ""}
                                {l.quantity !== "" && l.quantity != null ? ` · Qty: ${l.quantity}` : ""}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 shrink-0 flex-wrap justify-end">
                            <span
                              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                              className="font-medium"
                            >
                              {formatMoney(Number(l.price))}
                            </span>
                            <button
                              onClick={() => {
                                if (quickEditId === l.id) {
                                  setQuickEditId(null);
                                } else {
                                  setQuickEditId(l.id);
                                  setQuickEditDraft({
                                    price: String(l.price ?? ""),
                                    quantity: l.quantity != null ? String(l.quantity) : "",
                                  });
                                }
                              }}
                              className="text-xs font-medium underline"
                              style={{ color: SLATE }}
                            >
                              {quickEditId === l.id ? "Close" : "Quick edit"}
                            </button>
                            {l.status === "active" && (
                              <button
                                onClick={() => pauseListing(l.id)}
                                className="text-xs font-medium underline"
                                style={{ color: SLATE }}
                              >
                                Pause
                              </button>
                            )}
                            {l.status === "paused" && (
                              <button
                                onClick={() => resumeListing(l.id)}
                                className="text-xs font-medium underline"
                                style={{ color: SAGE }}
                              >
                                Resume
                              </button>
                            )}
                            {l.status === "active" && (
                              <button
                                onClick={() => markListingSoldOut(l.id)}
                                className="text-xs font-medium underline"
                                style={{ color: SLATE }}
                              >
                                Mark out of stock
                              </button>
                            )}
                            {l.status === "sold" && (
                              <button
                                onClick={() => markListingInStock(l.id)}
                                className="text-xs font-medium underline"
                                style={{ color: SAGE }}
                              >
                                Mark in stock
                              </button>
                            )}
                            <button
                              onClick={() => duplicateListing(l)}
                              className="text-xs font-medium underline"
                              style={{ color: SLATE }}
                            >
                              Duplicate
                            </button>
                            <button onClick={() => startEdit(l)} aria-label="Edit">
                              <Pencil size={16} style={{ color: SLATE }} />
                            </button>
                            <button onClick={() => deleteListing(l.id)} aria-label="Delete">
                              <Trash2 size={16} style={{ color: BERRY }} />
                            </button>
                          </div>
                        </div>
                        {quickEditId === l.id && (
                          <div
                            className="mt-3 pt-3 flex items-end gap-3 flex-wrap"
                            style={{ borderTop: "1px solid #EFEBE0" }}
                          >
                            <div>
                              <label className="block text-xs font-medium mb-1" style={{ color: INK }}>
                                Price
                              </label>
                              <input
                                type="number"
                                min="0"
                                step="0.01"
                                value={quickEditDraft.price}
                                onChange={(e) => setQuickEditDraft((d) => ({ ...d, price: e.target.value }))}
                                className="w-28 px-2 py-1.5 rounded-lg border outline-none text-sm"
                                style={{ borderColor: "#DDD8CC" }}
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-medium mb-1" style={{ color: INK }}>
                                Quantity
                              </label>
                              <input
                                type="number"
                                min="0"
                                step="1"
                                value={quickEditDraft.quantity}
                                onChange={(e) => setQuickEditDraft((d) => ({ ...d, quantity: e.target.value }))}
                                className="w-24 px-2 py-1.5 rounded-lg border outline-none text-sm"
                                style={{ borderColor: "#DDD8CC" }}
                              />
                            </div>
                            <button
                              onClick={async () => {
                                await quickUpdateListing(l.id, {
                                  price: quickEditDraft.price,
                                  quantity: quickEditDraft.quantity,
                                });
                                setQuickEditId(null);
                              }}
                              className="px-3 py-1.5 rounded-lg text-sm font-medium"
                              style={{ backgroundColor: MARIGOLD, color: INK }}
                            >
                              Save
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <h3 id="seller-sales" className="text-lg font-semibold mt-10 mb-3 scroll-mt-24" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
                  Orders & delivery
                </h3>
                {mySales.length > 0 && (
                  <div className="flex items-center gap-2 mb-3 overflow-x-auto">
                    {SALES_TABS.map((t) => {
                      const count =
                        t.key === "all"
                          ? mySales.length
                          : mySales.filter((o) => getSellerOrderStatus(o, currentUser) === t.key).length;
                      if (t.key !== "all" && count === 0) return null;
                      return (
                        <button
                          key={t.key}
                          onClick={() => setRoute((previous) => ({ ...previous, sellerSection: "orders", salesTab: t.key }))}
                          className="px-3 py-1.5 rounded-lg text-xs font-medium shrink-0"
                          style={{
                            backgroundColor: salesTab === t.key ? INK : "white",
                            color: salesTab === t.key ? "white" : SLATE,
                            border: `1px solid ${salesTab === t.key ? INK : "#DDD8CC"}`,
                          }}
                        >
                          {t.label} ({count})
                        </button>
                      );
                    })}
                  </div>
                )}
                {mySales.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    No sales yet.
                  </p>
                ) : filteredMySales.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    Nothing in this tab.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {filteredMySales.map((o) => {
                      const myItems = o.items.filter((i) => i.ownerUsername === currentUser);
                      const myRevenue = myItems.reduce((s, i) => s + i.price * i.qty, 0);
                      return (
                        <div key={o.id} className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium flex items-center gap-2" style={{ color: INK }}>
                              {o.buyerName}
                              {o.paymentStatus === "held" && <Tag color={MARIGOLD}>Held</Tag>}
                              {o.paymentStatus === "released" && <Tag color={SAGE}>Released</Tag>}
                              {o.paymentStatus === "refunded" && <Tag color={BERRY}>Refunded</Tag>}
                              {o.paymentStatus === "refund_pending" && <Tag color={MARIGOLD}>Refund pending</Tag>}
                            </span>
                            <span
                              className="text-sm font-semibold"
                              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                            >
                              {formatMoney(myRevenue)}
                            </span>
                          </div>
                          <div className="text-xs mb-2 flex items-center gap-2" style={{ color: SLATE }}>
                            <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                              {orderNumber(o.id)}
                            </span>
                            · {new Date(o.createdAt).toLocaleString()}
                            <button
                              onClick={() => setPackingSlipOrder(o)}
                              className="text-xs font-medium underline ml-auto"
                              style={{ color: INK }}
                            >
                              Print packing slip
                            </button>
                          </div>
                          {o.shippingAddress && (
                            <div
                              className="text-xs mb-3 p-2 rounded-lg"
                              style={{ backgroundColor: CANVAS, color: INK }}
                            >
                              <div><span className="font-medium">Deliver to:</span> {o.shippingAddress.fullName}</div>
                              <div>{o.shippingAddress.street}, {o.shippingAddress.city}{o.shippingAddress.state ? `, ${o.shippingAddress.state}` : ""} {o.shippingAddress.zip}, {o.shippingAddress.country}</div>
                              {o.shippingAddress.phone && <div className="mt-1"><span className="font-medium">Contact:</span> <a href={`tel:${o.shippingAddress.phone}`} className="underline">{o.shippingAddress.phone}</a></div>}
                              {o.shippingAddress.deliveryInstructions && <div className="mt-1"><span className="font-medium">Private instructions:</span> {o.shippingAddress.deliveryInstructions}</div>}
                              {o.shippingAddress.preferredDeliveryTime && <div className="mt-1"><span className="font-medium">Preferred time:</span> {o.shippingAddress.preferredDeliveryTime}</div>}
                              <a href={`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent([o.shippingAddress.street, o.shippingAddress.city, o.shippingAddress.state, o.shippingAddress.country].filter(Boolean).join(", "))}`} target="_blank" rel="noopener noreferrer" className="inline-block mt-1 underline font-medium">Open address in map</a>
                              {(o.shippingAddress.locationPhotos || []).length > 0 && (
                                <div className="mt-2"><div className="font-medium mb-1">Private location photos</div><div className="flex gap-2 flex-wrap">{o.shippingAddress.locationPhotos.map((photo, index) => <img key={index} src={photo} alt={`Delivery location ${index + 1}`} className="w-20 h-20 object-cover rounded-lg border" style={{ borderColor: "#DDD8CC" }} />)}</div></div>
                              )}
                            </div>
                          )}
                          {(o.payouts || []).length > 0 && (() => {
                            const payout = o.payouts[0];
                            const label = { queued: "Payout queued", processing: "Payout processing", paid: "Paid to bank", failed: "Payout failed", reversed: "Payout reversed", request_unknown: "Payout being verified", needs_bank: "Bank details required" }[payout.status] || payout.status;
                            return <div className="text-xs mb-3 p-2 rounded-lg border" style={{ borderColor: payout.status === "paid" ? SAGE : payout.status === "failed" || payout.status === "reversed" ? BERRY : MARIGOLD }}><span className="font-semibold">{label}</span> · {formatMoney(payout.amount, "NGN")}{payout.failureReason ? <div className="mt-1">{payout.failureReason}</div> : null}</div>;
                          })()}
                          {o.isDisputed && getMyDisputeForOrder(o.id) && (
                            <div className="mb-3 p-3 rounded-lg border" style={{ borderColor: BERRY, backgroundColor: "#FFF7F5" }}>
                              <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                                <span className="text-xs font-semibold" style={{ color: BERRY }}>Active dispute — payment locked</span>
                                <Tag color={MARIGOLD}>
                                  {getMyDisputeForOrder(o.id).status === "in_review" ? "Under review" : "Open"}
                                </Tag>
                              </div>
                              <p className="text-xs mb-1" style={{ color: INK }}>
                                <span className="font-medium">Reason:</span> {getMyDisputeForOrder(o.id).reason || "Not specified"}
                              </p>
                              {getMyDisputeForOrder(o.id).buyer_statement && (
                                <p className="text-xs mb-2" style={{ color: SLATE }}>
                                  <span className="font-medium" style={{ color: INK }}>Buyer statement:</span> {getMyDisputeForOrder(o.id).buyer_statement}
                                </p>
                              )}
                              <button
                                onClick={() => respondToDispute(getMyDisputeForOrder(o.id).id)}
                                className="text-xs font-medium underline"
                                style={{ color: INK }}
                              >
                                {getMyDisputeForOrder(o.id).seller_statement ? "Update my response" : "Respond to dispute"}
                              </button>
                            </div>
                          )}
                          <div className="space-y-2">
                            {myItems.map((i) => {
                              const trackKey = `${o.id}-${i.id}`;
                              const trackDraft =
                                trackingDrafts[trackKey] !== undefined
                                  ? trackingDrafts[trackKey]
                                  : i.trackingNumber || "";
                              const estimateDraft = deliveryEstimateDrafts[trackKey] || {
                                start: i.estimatedDeliveryStart || "",
                                end: i.estimatedDeliveryEnd || "",
                              };
                              const driverAssignment = deliveryAssignments[i.id] || null;
                              const driverDraft = deliveryAssignmentDrafts[i.id] || {
                                driverName: driverAssignment?.driverName || "",
                                driverPhone: driverAssignment?.driverPhone || "",
                                deliveryFee: driverAssignment?.deliveryFee ? String(driverAssignment.deliveryFee) : "",
                                paymentMethod: driverAssignment?.paymentMethod || "cash",
                                pickupAt: toLocalDateTimeInput(driverAssignment?.pickupAt),
                                deliveryDueAt: toLocalDateTimeInput(driverAssignment?.deliveryDueAt),
                                packageDescription: driverAssignment?.packageDescription || i.title || "",
                              };
                              const driverSecret = deliveryAssignmentSecrets[i.id] || null;
                              return (
                                <div
                                  key={i.id}
                                  className="text-xs pt-2 border-t"
                                  style={{ borderColor: "#EFEBE0", color: SLATE }}
                                >
                                  <div className="flex items-center justify-between gap-3">
                                    <span>
                                      {i.title} × {i.qty}
                                    </span>
                                    <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
                                      <Tag color={FULFILLMENT_COLOR[i.fulfillmentStatus] || FULFILLMENT_COLOR.new}>
                                        {FULFILLMENT_LABEL[i.fulfillmentStatus] || "New"}
                                      </Tag>
                                      {i.buyerConfirmedAt && <Tag color={SAGE}>Buyer confirmed</Tag>}
                                      {i.deliveryTokenSentAt && <Tag color={MARIGOLD}>Token received</Tag>}
                                      <select
                                        value={i.fulfillmentStatus || "new"}
                                        onChange={(e) => updateItemFulfillment(o.id, i.id, e.target.value)}
                                        className="px-2 py-1 rounded-lg border outline-none text-xs"
                                        style={{ borderColor: "#DDD8CC", color: INK }}
                                        disabled={i.carrier === "Self delivery"}
                                        title={i.carrier === "Self delivery" ? "Use the Self delivery steps below" : "Update fulfillment status"}
                                      >
                                        <option value="new">New</option>
                                        <option value="preparing">Preparing</option>
                                        <option value="shipped">Shipped</option>
                                        <option value="delivered">Delivered</option>
                                        <option value="cancelled">Cancelled</option>
                                        <option value="returned">Returned</option>
                                      </select>
                                    </div>
                                  </div>
                                  <div className="mt-3 p-2 rounded-lg" style={{ backgroundColor: CANVAS }}>
                                    <TrackingTimeline
                                      item={i}
                                      orderCreatedAt={o.createdAt}
                                      ink={INK}
                                      slate={SLATE}
                                      sage={SAGE}
                                      berry={BERRY}
                                    />
                                  </div>
                                  {i.cancellationStatus === "requested" && (
                                    <div className="mt-2 p-2 rounded-lg border" style={{ borderColor: MARIGOLD, backgroundColor: CANVAS }}>
                                      <div className="font-medium" style={{ color: INK }}>Buyer requested cancellation</div>
                                      <div className="mt-1">Reason: {i.cancellationReason}</div>
                                      <div className="flex gap-3 mt-2">
                                        <button onClick={() => respondToCancellation(o.id, i.id, "approved")} className="font-medium underline" style={{ color: SAGE }}>Approve</button>
                                        <button onClick={() => respondToCancellation(o.id, i.id, "denied")} className="font-medium underline" style={{ color: BERRY }}>Deny</button>
                                      </div>
                                    </div>
                                  )}
                                  {i.cancellationStatus === "approved" && <div className="mt-2"><Tag color={SAGE}>Cancellation approved — refund review</Tag></div>}
                                  {i.cancellationStatus === "denied" && <div className="mt-2"><Tag color={BERRY}>Cancellation denied</Tag></div>}
                                  {i.deliveryTokenSentAt && i.deliveryToken && !["shipped", "delivered"].includes(i.fulfillmentStatus) && (
                                    <div className="mt-2 p-2 rounded-lg border" style={{ borderColor: SAGE, backgroundColor: CANVAS }}>
                                      <div className="text-xs font-medium" style={{ color: INK }}>Buyer sent delivery token</div>
                                      <div className="text-lg font-semibold tracking-widest" style={{ color: INK, fontFamily: "'IBM Plex Mono', monospace" }}>{i.deliveryToken}</div>
                                      <div className="text-xs" style={{ color: SLATE }}>The token is also in Messages. Delivery photo is still required before payment release.</div>
                                    </div>
                                  )}
                                  {!['cancelled', 'returned'].includes(i.fulfillmentStatus) && (
                                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                                      <select
                                        value={i.carrier || ""}
                                        onChange={(e) => updateItemCarrier(o.id, i.id, e.target.value)}
                                        className="px-2 py-1 rounded-lg border outline-none text-xs bg-white"
                                        style={{ borderColor: "#DDD8CC", color: INK }}
                                      >
                                        <option value="">Carrier (optional)</option>
                                        {SHIPPING_CARRIERS.map((c) => (
                                          <option key={c} value={c}>
                                            {c}
                                          </option>
                                        ))}
                                      </select>
                                      {i.carrier !== "Self delivery" && (
                                        <>
                                          <input
                                            value={trackDraft}
                                            onChange={(e) =>
                                              setTrackingDrafts((d) => ({ ...d, [trackKey]: e.target.value }))
                                            }
                                            placeholder="Tracking number (optional)"
                                            className="flex-1 px-2 py-1 rounded-lg border outline-none text-xs"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                          <button
                                            onClick={async () => {
                                              await updateItemTracking(o.id, i.id, trackDraft.trim());
                                              setTrackingDrafts((d) => {
                                                const next = { ...d };
                                                delete next[trackKey];
                                                return next;
                                              });
                                            }}
                                            className="px-2 py-1 rounded-lg text-xs font-medium"
                                            style={{ backgroundColor: MARIGOLD, color: INK }}
                                          >
                                            Save
                                          </button>
                                        </>
                                      )}
                                    </div>
                                  )}
                                  {i.carrier === "Local Delivery Driver" && !['cancelled', 'returned'].includes(i.fulfillmentStatus) && (
                                    <div className="mt-3 p-3 rounded-xl border" style={{ borderColor: SAGE, backgroundColor: "#F3F8F4" }}>
                                      <div className="flex items-center justify-between gap-2 flex-wrap">
                                        <div>
                                          <div className="text-sm font-semibold" style={{ color: INK }}>Assign a Local Delivery Driver</div>
                                          <div className="text-xs mt-0.5" style={{ color: SLATE }}>
                                            The driver receives restricted access to this delivery only. Never share your Stallyard password.
                                          </div>
                                        </div>
                                        {driverAssignment && (
                                          <Tag color={driverAssignment.status === "revoked" ? BERRY : SAGE}>
                                            {driverAssignment.status === "revoked" ? "Access revoked" : "Assigned"}
                                          </Tag>
                                        )}
                                      </div>
                                      <div className="grid sm:grid-cols-2 gap-2 mt-3">
                                        <label className="text-xs">
                                          <span className="block mb-1 font-medium" style={{ color: INK }}>Driver's full name</span>
                                          <input
                                            value={driverDraft.driverName}
                                            onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, driverName: e.target.value } }))}
                                            placeholder="Driver's full name"
                                            className="w-full px-2 py-2 rounded-lg border bg-white outline-none"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                        </label>
                                        <label className="text-xs">
                                          <span className="block mb-1 font-medium" style={{ color: INK }}>Nigerian phone number</span>
                                          <input
                                            type="tel"
                                            value={driverDraft.driverPhone}
                                            onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, driverPhone: e.target.value } }))}
                                            placeholder="0801 234 5678"
                                            className="w-full px-2 py-2 rounded-lg border bg-white outline-none"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                        </label>
                                        <label className="text-xs">
                                          <span className="block mb-1 font-medium" style={{ color: INK }}>Agreed delivery fee (₦)</span>
                                          <input
                                            type="number"
                                            min="1"
                                            step="1"
                                            value={driverDraft.deliveryFee}
                                            onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, deliveryFee: e.target.value } }))}
                                            placeholder="5000"
                                            className="w-full px-2 py-2 rounded-lg border bg-white outline-none"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                        </label>
                                        <label className="text-xs">
                                          <span className="block mb-1 font-medium" style={{ color: INK }}>Driver payment method</span>
                                          <select
                                            value={driverDraft.paymentMethod}
                                            onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, paymentMethod: e.target.value } }))}
                                            className="w-full px-2 py-2 rounded-lg border bg-white outline-none"
                                            style={{ borderColor: "#DDD8CC" }}
                                          >
                                            <option value="cash">Cash</option>
                                            <option value="bank_transfer">Bank transfer</option>
                                          </select>
                                        </label>
                                        <label className="text-xs">
                                          <span className="block mb-1 font-medium" style={{ color: INK }}>Expected pickup</span>
                                          <input
                                            type="datetime-local"
                                            value={driverDraft.pickupAt}
                                            onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, pickupAt: e.target.value } }))}
                                            className="w-full px-2 py-2 rounded-lg border bg-white outline-none"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                        </label>
                                        <label className="text-xs">
                                          <span className="block mb-1 font-medium" style={{ color: INK }}>Expected delivery</span>
                                          <input
                                            type="datetime-local"
                                            min={driverDraft.pickupAt || undefined}
                                            value={driverDraft.deliveryDueAt}
                                            onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, deliveryDueAt: e.target.value } }))}
                                            className="w-full px-2 py-2 rounded-lg border bg-white outline-none"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                        </label>
                                      </div>
                                      <label className="text-xs block mt-2">
                                        <span className="block mb-1 font-medium" style={{ color: INK }}>Package description</span>
                                        <textarea
                                          value={driverDraft.packageDescription}
                                          onChange={(e) => setDeliveryAssignmentDrafts((all) => ({ ...all, [i.id]: { ...driverDraft, packageDescription: e.target.value } }))}
                                          maxLength={500}
                                          rows={2}
                                          className="w-full px-2 py-2 rounded-lg border bg-white outline-none resize-y"
                                          style={{ borderColor: "#DDD8CC" }}
                                        />
                                      </label>
                                      <div className="flex gap-2 mt-3 flex-wrap">
                                        {driverAssignment?.status !== "delivered" && (
                                          <button
                                            type="button"
                                            onClick={() => saveLocalDriverAssignment(i.id, driverDraft)}
                                            disabled={deliveryAssignmentSavingKey === i.id}
                                            className="px-3 py-2 rounded-lg text-xs font-semibold disabled:opacity-50"
                                            style={{ backgroundColor: SAGE, color: "white" }}
                                          >
                                            {deliveryAssignmentSavingKey === i.id
                                              ? "Saving…"
                                              : driverAssignment
                                                ? "Update assignment and create new access"
                                                : "Create driver link"}
                                          </button>
                                        )}
                                        {driverAssignment?.status === "assigned" && (
                                          <button
                                            type="button"
                                            onClick={() => revokeLocalDriverAccess(i.id, driverAssignment.id)}
                                            disabled={deliveryAssignmentSavingKey === i.id}
                                            className="px-3 py-2 rounded-lg border text-xs font-semibold bg-white disabled:opacity-50"
                                            style={{ borderColor: BERRY, color: BERRY }}
                                          >
                                            Revoke access
                                          </button>
                                        )}
                                        {driverAssignment && ["assigned", "revoked"].includes(driverAssignment.status) && (
                                          <button
                                            type="button"
                                            onClick={() => regenerateLocalDriverAccess(i.id, driverAssignment.id)}
                                            disabled={deliveryAssignmentSavingKey === i.id}
                                            className="px-3 py-2 rounded-lg border text-xs font-semibold bg-white disabled:opacity-50"
                                            style={{ borderColor: INK, color: INK }}
                                          >
                                            Create new link and code
                                          </button>
                                        )}
                                      </div>
                                      {driverAssignment && (
                                        <div className="mt-3 text-xs" style={{ color: SLATE }}>
                                          Access expires {new Date(driverAssignment.accessExpiresAt).toLocaleString()}.
                                          {!driverSecret && driverAssignment.status !== "revoked" && " Create a new link and code if you no longer have the originals."}
                                        </div>
                                      )}
                                      {driverAssignment?.status === "delivered" && (
                                        <div className="mt-3 p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                                          <div className="flex items-center justify-between gap-2 flex-wrap">
                                            <div className="text-xs font-semibold" style={{ color: INK }}>Driver fee</div>
                                            <Tag color={driverAssignment.paymentStatus === "confirmed" ? SAGE : MARIGOLD}>
                                              {driverAssignment.paymentStatus === "confirmed"
                                                ? "Driver confirmed paid"
                                                : driverAssignment.paymentStatus === "seller_marked_paid"
                                                  ? "Waiting for driver confirmation"
                                                  : "Payment pending"}
                                            </Tag>
                                          </div>
                                          <div className="mt-2 text-xs" style={{ color: SLATE }}>
                                            Agreed fee: <strong style={{ color: INK }}>{formatMoney(driverAssignment.deliveryFee)}</strong> by {String(driverAssignment.paymentMethod || "cash").replace(/_/g, " ")}.
                                          </div>
                                          {driverAssignment.paymentMethod === "bank_transfer" && driverAssignment.hasDriverBankDetails && (
                                            <div className="mt-2 p-2 rounded-lg" style={{ backgroundColor: "#F6F3EC", color: INK }}>
                                              <div>{driverAssignment.driverBankName}</div>
                                              <div className="font-medium">{driverAssignment.driverAccountName}</div>
                                              <div style={{ fontFamily: "'IBM Plex Mono', monospace" }}>{driverAssignment.driverAccountNumber}</div>
                                            </div>
                                          )}
                                          {driverAssignment.paymentMethod === "bank_transfer" && !driverAssignment.hasDriverBankDetails && (
                                            <div className="mt-2 text-xs" style={{ color: BERRY }}>Waiting for the driver to add bank details.</div>
                                          )}
                                          {driverAssignment.openReportCount > 0 && (
                                            <div className="mt-2 text-xs font-medium" style={{ color: BERRY }}>The driver submitted a report that is awaiting Stallyard review.</div>
                                          )}
                                          {driverAssignment.paymentStatus === "pending" && (driverAssignment.paymentMethod === "cash" || driverAssignment.hasDriverBankDetails) && (
                                            <button
                                              type="button"
                                              onClick={() => markLocalDriverPaid(i.id, driverAssignment)}
                                              disabled={deliveryAssignmentSavingKey === i.id}
                                              className="mt-3 px-3 py-2 rounded-lg text-xs font-semibold disabled:opacity-50"
                                              style={{ backgroundColor: MARIGOLD, color: INK }}
                                            >
                                              {deliveryAssignmentSavingKey === i.id ? "Saving…" : "Mark driver fee paid"}
                                            </button>
                                          )}
                                        </div>
                                      )}
                                      {driverSecret && (
                                        <div className="mt-3 p-3 rounded-lg border bg-white" style={{ borderColor: MARIGOLD }}>
                                          <div className="font-semibold text-xs" style={{ color: INK }}>Share these separately with the assigned driver</div>
                                          <div className="mt-2">
                                            <div className="text-xs font-medium" style={{ color: INK }}>One-time delivery link</div>
                                            <div className="flex gap-2 mt-1">
                                              <input readOnly value={driverSecret.accessUrl} className="flex-1 min-w-0 px-2 py-1 rounded border text-xs" style={{ borderColor: "#DDD8CC" }} />
                                              <button type="button" onClick={() => copyDeliveryAccessValue(driverSecret.accessUrl, "Driver link")} className="px-2 py-1 rounded border text-xs font-medium bg-white" style={{ borderColor: SAGE, color: INK }}>Copy link</button>
                                            </div>
                                          </div>
                                          <div className="mt-2">
                                            <div className="text-xs font-medium" style={{ color: INK }}>Six-digit activation code</div>
                                            <div className="flex items-center gap-2 mt-1">
                                              <span className="text-lg font-semibold tracking-widest" style={{ color: INK, fontFamily: "'IBM Plex Mono', monospace" }}>{driverSecret.activationCode}</span>
                                              <button type="button" onClick={() => copyDeliveryAccessValue(driverSecret.activationCode, "Activation code")} className="px-2 py-1 rounded border text-xs font-medium bg-white" style={{ borderColor: SAGE, color: INK }}>Copy code</button>
                                            </div>
                                          </div>
                                          <p className="text-xs mt-2" style={{ color: BERRY }}>Do not send your Stallyard password. The driver link has access to this delivery only.</p>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                  {i.carrier === "Self delivery" && !['cancelled', 'returned'].includes(i.fulfillmentStatus) && (
                                    <div className="mt-3 p-3 rounded-xl border" style={{ borderColor: MARIGOLD, backgroundColor: "#FFF9EF" }}>
                                      <div className="flex items-center justify-between gap-2 flex-wrap">
                                        <div>
                                          <div className="text-sm font-semibold" style={{ color: INK }}>Self delivery</div>
                                          <div className="text-xs mt-0.5" style={{ color: SLATE }}>
                                            Complete each step in order. The buyer can follow the progress.
                                          </div>
                                        </div>
                                        <Tag color={i.selfDeliveryStatus === "delivered" ? SAGE : MARIGOLD}>
                                          {({ started: "Started", on_my_way: "On my way", arrived: "I’m here", delivered: "Delivered" }[i.selfDeliveryStatus] || "Not started")}
                                        </Tag>
                                      </div>

                                      {!i.selfDeliveryStatus && (
                                        <button
                                          type="button"
                                          onClick={() => runSelfDeliveryStep(o.id, i.id, "start")}
                                          disabled={selfDeliveryActionKey === `${o.id}-${i.id}-start`}
                                          className="mt-3 px-4 py-2 rounded-lg text-xs font-semibold disabled:opacity-50"
                                          style={{ backgroundColor: INK, color: "white" }}
                                        >
                                          {selfDeliveryActionKey === `${o.id}-${i.id}-start` ? "Starting…" : "Start self delivery"}
                                        </button>
                                      )}

                                      {i.selfDeliveryStatus === "started" && (
                                        <button
                                          type="button"
                                          onClick={() => runSelfDeliveryStep(o.id, i.id, "on_my_way")}
                                          disabled={selfDeliveryActionKey === `${o.id}-${i.id}-on_my_way`}
                                          className="mt-3 px-4 py-2 rounded-lg text-xs font-semibold disabled:opacity-50"
                                          style={{ backgroundColor: MARIGOLD, color: INK }}
                                        >
                                          {selfDeliveryActionKey === `${o.id}-${i.id}-on_my_way` ? "Saving…" : "On my way"}
                                        </button>
                                      )}

                                      {i.selfDeliveryStatus === "on_my_way" && (
                                        <div className="mt-3 p-3 rounded-lg bg-white border" style={{ borderColor: "#E7DDC9" }}>
                                          {!i.deliveryPersonSelfieUrl ? (
                                            <>
                                              <div className="text-xs font-semibold" style={{ color: INK }}>Required: delivery-person selfie</div>
                                              <div className="text-xs mt-1" style={{ color: SLATE }}>Take a current photo of the person making this delivery before continuing.</div>
                                              <button
                                                type="button"
                                                onClick={() => setDeliverySelfieCameraTarget({ orderId: o.id, itemId: i.id })}
                                                className="inline-block mt-2 px-3 py-2 rounded-lg border bg-white text-xs font-medium"
                                                style={{ borderColor: INK, color: INK }}
                                              >
                                                Open live selfie camera
                                              </button>
                                            </>
                                          ) : (
                                            <>
                                              <div className="flex items-center gap-3 flex-wrap">
                                                <img src={i.deliveryPersonSelfieUrl} alt="Delivery person selfie" className="w-20 h-20 rounded-lg object-cover border" style={{ borderColor: "#DDD8CC" }} />
                                                <div>
                                                  <div className="text-xs font-semibold" style={{ color: SAGE }}>Delivery-person selfie saved</div>
                                                  <div className="text-xs mt-1" style={{ color: SLATE }}>GPS sharing is optional. Use the location controls below if desired.</div>
                                                </div>
                                              </div>
                                              <button
                                                type="button"
                                                onClick={() => runSelfDeliveryStep(o.id, i.id, "arrived")}
                                                disabled={selfDeliveryActionKey === `${o.id}-${i.id}-arrived`}
                                                className="mt-3 px-4 py-2 rounded-lg text-xs font-semibold disabled:opacity-50"
                                                style={{ backgroundColor: MARIGOLD, color: INK }}
                                              >
                                                {selfDeliveryActionKey === `${o.id}-${i.id}-arrived` ? "Saving…" : "I’m here"}
                                              </button>
                                            </>
                                          )}
                                        </div>
                                      )}

                                      {i.selfDeliveryStatus === "arrived" && (
                                        <div className="mt-3 p-3 rounded-lg bg-white border" style={{ borderColor: "#E7DDC9" }}>
                                          <div className="text-xs font-semibold" style={{ color: INK }}>Required: delivery-proof photo</div>
                                          <div className="text-xs mt-1" style={{ color: SLATE }}>Take a live handoff photo before completing delivery.</div>
                                          {i.proofOfDeliveryUrl ? (
                                            <img src={i.proofOfDeliveryUrl} alt="Delivery proof" className="mt-2 w-24 h-24 rounded-lg object-cover border" style={{ borderColor: "#DDD8CC" }} />
                                          ) : (
                                            <button type="button" onClick={() => setDeliveryPhotoTarget({ orderId: o.id, itemId: i.id })} disabled={uploadingPodKey === trackKey} className="inline-block mt-2 px-3 py-2 rounded-lg border bg-white text-xs font-medium disabled:opacity-50" style={{ borderColor: INK, color: INK }}>Take delivery photo</button>
                                          )}
                                          <button
                                            type="button"
                                            onClick={() => runSelfDeliveryStep(o.id, i.id, "delivered")}
                                            disabled={!i.proofOfDeliveryUrl || selfDeliveryActionKey === `${o.id}-${i.id}-delivered`}
                                            className="block mt-2 px-4 py-2 rounded-lg text-xs font-semibold disabled:opacity-40"
                                            style={{ backgroundColor: SAGE, color: "white" }}
                                          >
                                            {selfDeliveryActionKey === `${o.id}-${i.id}-delivered` ? "Completing…" : "Delivered"}
                                          </button>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                  {!['cancelled', 'returned', 'delivered'].includes(i.fulfillmentStatus) && (
                                    <div className="mt-2 p-2 rounded-lg border" style={{ borderColor: "#DDD8CC", backgroundColor: CANVAS }}>
                                      <div className="text-xs font-medium mb-1" style={{ color: INK }}>Estimated delivery</div>
                                      <div className="text-xs mb-2" style={{ color: SLATE }}>
                                        Enter one date for “expected by,” or add an end date to show a delivery range.
                                      </div>
                                      <div className="flex items-end gap-2 flex-wrap">
                                        <label className="text-xs">
                                          <span className="block mb-1">Start date</span>
                                          <input
                                            type="date"
                                            value={estimateDraft.start}
                                            onChange={(e) => setDeliveryEstimateDrafts((drafts) => ({
                                              ...drafts,
                                              [trackKey]: { ...estimateDraft, start: e.target.value },
                                            }))}
                                            className="px-2 py-1 rounded-lg border outline-none bg-white"
                                            style={{ borderColor: "#DDD8CC", color: INK }}
                                          />
                                        </label>
                                        <label className="text-xs">
                                          <span className="block mb-1">End date (optional)</span>
                                          <input
                                            type="date"
                                            min={estimateDraft.start || undefined}
                                            value={estimateDraft.end}
                                            onChange={(e) => setDeliveryEstimateDrafts((drafts) => ({
                                              ...drafts,
                                              [trackKey]: { ...estimateDraft, end: e.target.value },
                                            }))}
                                            className="px-2 py-1 rounded-lg border outline-none bg-white"
                                            style={{ borderColor: "#DDD8CC", color: INK }}
                                          />
                                        </label>
                                        <button
                                          onClick={async () => {
                                            const saved = await updateEstimatedDelivery(o.id, i.id, estimateDraft.start, estimateDraft.end);
                                            if (saved) setDeliveryEstimateDrafts((drafts) => {
                                              const next = { ...drafts };
                                              delete next[trackKey];
                                              return next;
                                            });
                                          }}
                                          className="px-3 py-1 rounded-lg text-xs font-medium"
                                          style={{ backgroundColor: MARIGOLD, color: INK }}
                                        >
                                          Save estimate
                                        </button>
                                      </div>
                                    </div>
                                  )}
                                  {i.fulfillmentStatus === "shipped" && (i.carrier !== "Self delivery" || !!i.deliveryPersonSelfieUrl) && (
                                    <div className="mt-2 p-2 rounded-lg border" style={{ borderColor: SAGE, backgroundColor: CANVAS }}>
                                      <div className="text-xs font-medium" style={{ color: INK }}>Live delivery location</div>
                                      <div className="text-xs mt-1" style={{ color: SLATE }}>
                                        Optional. The buyer can see your phone’s location only for this delivery. Keep this page open for live updates.
                                      </div>
                                      {i.liveLocationEnabled && i.liveLocationUpdatedAt && (
                                        <div className="text-xs mt-1" style={{ color: SAGE }}>
                                          Sharing active · Last updated {new Date(i.liveLocationUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                        </div>
                                      )}
                                      <div className="flex gap-2 mt-2 flex-wrap">
                                        <button
                                          onClick={() => startSellerLocationSharing(o.id, i.id)}
                                          className="px-3 py-1 rounded-lg text-xs font-medium"
                                          style={{ backgroundColor: SAGE, color: "white" }}
                                        >
                                          {i.liveLocationEnabled ? "Resume phone updates" : "Start sharing location"}
                                        </button>
                                        {i.liveLocationEnabled && (
                                          <button
                                            onClick={() => stopSellerLocationSharing(o.id, i.id)}
                                            className="px-3 py-1 rounded-lg border text-xs font-medium bg-white"
                                            style={{ borderColor: BERRY, color: BERRY }}
                                          >
                                            Stop sharing
                                          </button>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                  {i.fulfillmentStatus === "delivered" && (
                                    <div className="mt-2">
                                      <div className="text-xs font-medium mb-1" style={{ color: INK }}>
                                        Proof of delivery
                                      </div>
                                      {i.proofOfDeliveryUrl ? (
                                        <a href={i.proofOfDeliveryUrl} target="_blank" rel="noreferrer">
                                          <img
                                            src={i.proofOfDeliveryUrl}
                                            alt="Proof of delivery"
                                            className="w-20 h-20 object-cover rounded-lg border"
                                            style={{ borderColor: "#DDD8CC" }}
                                          />
                                        </a>
                                      ) : (
                                        <button type="button" onClick={() => setDeliveryPhotoTarget({ orderId: o.id, itemId: i.id })} disabled={uploadingPodKey === trackKey} className="inline-block px-2 py-1 rounded-lg border text-xs font-medium" style={{ borderColor: "#DDD8CC", backgroundColor: "white", color: INK }}>Take delivery photo</button>
                                      )}
                                    </div>
                                  )}
                                  {(i.fulfillmentStatus === "shipped" || i.fulfillmentStatus === "delivered") &&
                                    (o.paymentStatus === "released" ? (
                                      <div className="mt-2">
                                        <Tag color={SAGE}>Delivery completed — payment released</Tag>
                                      </div>
                                    ) : (
                                      <div className="mt-2 p-2 rounded-lg" style={{ backgroundColor: CANVAS }}>
                                        <div className="text-xs font-medium mb-1" style={{ color: INK }}>
                                          Buyer's delivery code
                                        </div>
                                        <div className="text-xs mb-2" style={{ color: SLATE }}>
                                          At handoff, ask the buyer for the 10-digit token, upload the delivery photo, then enter the token below.
                                        </div>
                                        {i.deliveryTokenSentAt && i.deliveryToken && (
                                          <div className="mb-2 p-2 rounded-lg border" style={{ borderColor: SAGE, backgroundColor: "white" }}>
                                            <div className="text-xs font-medium" style={{ color: INK }}>Buyer sent this token</div>
                                            <div className="text-lg font-semibold tracking-widest" style={{ color: INK, fontFamily: "'IBM Plex Mono', monospace" }}>{i.deliveryToken}</div>
                                            <div className="text-xs" style={{ color: SLATE }}>It was also added to your Messages.</div>
                                          </div>
                                        )}
                                        <div className="flex items-center gap-2 flex-wrap">
                                          <input
                                            value={redeemTokenDrafts[i.id] || ""}
                                            onChange={(e) =>
                                              setRedeemTokenDrafts((d) => ({ ...d, [i.id]: e.target.value }))
                                            }
                                            placeholder="10-digit code from buyer"
                                            maxLength={10}
                                            className="px-2 py-1 rounded-lg border outline-none text-xs w-36"
                                            style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                                          />
                                          <button
                                            onClick={() =>
                                              redeemDeliveryToken(o.id, i.id, (redeemTokenDrafts[i.id] || "").trim())
                                            }
                                            disabled={
                                              redeemingTokenKey === i.id ||
                                              !(redeemTokenDrafts[i.id] || "").trim() ||
                                              !i.proofOfDeliveryUrl || !i.deliveryTokenSentAt || !!i.deliveryTokenRedeemedAt || i.fulfillmentStatus !== "delivered"
                                            }
                                            className="px-2 py-1 rounded-lg text-xs font-medium disabled:opacity-50"
                                            style={{ backgroundColor: MARIGOLD, color: INK }}
                                          >
                                            {redeemingTokenKey === i.id ? "Checking…" : "Release payment"}
                                          </button>
                                        </div>
                                        <p className="text-xs mt-1" style={{ color: SLATE }}>
                                          Upload the delivery picture first, then enter the 10-digit token the buyer gives you after receiving and inspecting the item. Both are required to release payment.
                                        </p>
                                      </div>
                                    ))}
                                  {i.returnStatus === "requested" && (
                                    <div
                                      className="mt-2 p-2 rounded-lg"
                                      style={{ backgroundColor: "#FBF0DC" }}
                                    >
                                      <div className="mb-1" style={{ color: INK }}>
                                        <span className="font-medium">Return requested:</span> {i.returnReason}
                                        {i.returnNote ? ` — "${i.returnNote}"` : ""}
                                      </div>
                                      {i.returnEvidenceUrls && i.returnEvidenceUrls.length > 0 && (
                                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                                          {i.returnEvidenceUrls.map((url, idx) => (
                                            <a key={idx} href={url} target="_blank" rel="noreferrer">
                                              <img
                                                src={url}
                                                alt={`Evidence ${idx + 1}`}
                                                className="w-14 h-14 object-cover rounded-lg border"
                                                style={{ borderColor: "#DDD8CC" }}
                                              />
                                            </a>
                                          ))}
                                        </div>
                                      )}
                                      <div className="flex items-center gap-3">
                                        <button
                                          onClick={() => approveReturn(o.id, i.id)}
                                          className="text-xs font-medium underline"
                                          style={{ color: SAGE }}
                                        >
                                          Approve return
                                        </button>
                                        <button
                                          onClick={() => denyReturn(o.id, i.id)}
                                          className="text-xs font-medium underline"
                                          style={{ color: BERRY }}
                                        >
                                          Deny
                                        </button>
                                      </div>
                                    </div>
                                  )}
                                  {i.returnStatus === "approved" && (
                                    <div className="mt-2">
                                      <div className="flex items-center gap-2 flex-wrap mb-1">
                                        <Tag color={SAGE}>Return approved</Tag>
                                        {["held", "released"].includes(o.paymentStatus) && (
                                          <button
                                            onClick={() => refundOrder(o.id)}
                                            className="text-xs font-medium underline"
                                            style={{ color: BERRY }}
                                          >
                                            Refund buyer
                                          </button>
                                        )}
                                      </div>
                                      {i.returnTrackingNumber ? (
                                        <div className="text-xs" style={{ color: SLATE }}>
                                          Buyer's return tracking:{" "}
                                          <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                                            {i.returnTrackingNumber}
                                          </span>{" "}
                                          <a
                                            href={buildTrackingUrl(i.returnTrackingNumber)}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="underline font-medium"
                                            style={{ color: MARIGOLD }}
                                          >
                                            Track →
                                          </a>
                                        </div>
                                      ) : (
                                        <div className="text-xs" style={{ color: SLATE }}>
                                          Waiting on buyer to add return tracking.
                                        </div>
                                      )}
                                    </div>
                                  )}
                                  {i.returnStatus === "denied" && (
                                    <div className="mt-2">
                                      <Tag color={BERRY}>Return denied</Tag>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      );
                    })}
                    <p className="text-xs pt-1" style={{ color: SLATE }}>
                      Amounts shown are your gross sales before the marketplace commission. Payout status is tracked per order in the admin dashboard.
                    </p>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {view === "buyerHome" && currentUser && (
          <div>
            <div className="flex items-center justify-between gap-3 flex-wrap mb-1">
              <h2 className="text-2xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                Dashboard
              </h2>
              <div className="flex items-center gap-2 flex-wrap">
                {!currentMember?.isAdmin && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelected(null);
                      setView("dashboard");
                      window.scrollTo({ top: 0, behavior: "smooth" });
                    }}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white"
                    style={{ backgroundColor: INK }}
                  >
                    <Store size={17} />
                    Seller Dashboard
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setView("wallet")}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border bg-white text-sm font-semibold"
                  style={{ borderColor: SAGE, color: INK }}
                >
                  <Wallet size={17} />
                  Seller wallet · {formatMoney(walletNetAvailable, "NGN")}
                </button>
              </div>
            </div>
            <p className="text-sm mb-5" style={{ color: SLATE }}>
              Everything about your orders, messages, and alerts in one place.
            </p>

            <h3 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: SLATE }}>
              Needs your attention
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              <button
                onClick={() => setView("orders")}
                className="p-3 rounded-lg border bg-white text-left"
                style={{ borderColor: buyerTokensReadyCount ? MARIGOLD : "#DDD8CC" }}
              >
                <div
                  className="text-2xl font-semibold"
                  style={{ fontFamily: "'IBM Plex Mono', monospace", color: buyerTokensReadyCount ? MARIGOLD : INK }}
                >
                  {buyerTokensReadyCount}
                </div>
                <div className="text-xs font-medium" style={{ color: INK }}>
                  delivery token{buyerTokensReadyCount === 1 ? "" : "s"} ready
                </div>
                {buyerTokensReadyCount > 0 && (
                  <div className="text-xs mt-1" style={{ color: SLATE }}>
                    Review the order and send only after accepting the item →
                  </div>
                )}
              </button>
              <button
                onClick={() => setView("messages")}
                className="p-3 rounded-lg border bg-white text-left"
                style={{ borderColor: "#DDD8CC" }}
              >
                <div
                  className="text-2xl font-semibold"
                  style={{ fontFamily: "'IBM Plex Mono', monospace", color: unreadThreadsCount ? MARIGOLD : INK }}
                >
                  {unreadThreadsCount}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  unread messages
                </div>
              </button>
              <button
                onClick={() => {
                  setBuyerOrderSearch("");
                  setBuyerOrderStatusFilter("disputed");
                  setView("orders");
                }}
                className="p-3 rounded-lg border bg-white text-left"
                style={{ borderColor: "#DDD8CC" }}
              >
                <div
                  className="text-2xl font-semibold"
                  style={{ fontFamily: "'IBM Plex Mono', monospace", color: buyerOpenDisputesCount ? BERRY : INK }}
                >
                  {buyerOpenDisputesCount}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  open disputes
                </div>
              </button>
              <button
                onClick={() => setNotifPanelOpen(true)}
                className="p-3 rounded-lg border bg-white text-left"
                style={{ borderColor: "#DDD8CC" }}
              >
                <div
                  className="text-2xl font-semibold"
                  style={{ fontFamily: "'IBM Plex Mono', monospace", color: unreadNotifCount ? MARIGOLD : INK }}
                >
                  {unreadNotifCount}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  new alerts
                </div>
              </button>
            </div>

            {sellerReports.length > 0 && (
              <div className="mb-6">
                <h3 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: SLATE }}>My seller reports</h3>
                <div className="space-y-2">{(showAllSellerReports ? sellerReports : sellerReports.slice(0, 3)).map((report) => (
                  <div key={report.id} className="p-3 rounded-lg border bg-white text-xs" style={{ borderColor: "#DDD8CC" }}>
                    <div className="flex justify-between gap-2"><span className="font-medium" style={{ color: INK }}>{report.reference}</span><Tag color={report.status === "resolved" ? SAGE : report.status === "dismissed" ? SLATE : MARIGOLD}>{String(report.status).replace("_", " ")}</Tag></div>
                    <div className="mt-1" style={{ color: SLATE }}>{report.seller_display_name || report.seller_username} · {String(report.reason).replaceAll("_", " ")}{report.order_id ? ` · ${orderNumber(report.order_id)}` : ""}</div>
                  </div>
                ))}</div>
                {sellerReports.length > 3 && <button onClick={() => setShowAllSellerReports((shown) => !shown)} className="text-xs font-medium underline mt-2" style={{ color: SLATE }}>{showAllSellerReports ? "Show less" : `View all ${sellerReports.length} reports`}</button>}
              </div>
            )}

            <h3 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: SLATE }}>
              Orders
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#3B6E8F" }}>
                  {buyerOrdersWaitingToShip}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  waiting to ship
                </div>
              </div>
              <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#6B8F71" }}>
                  {buyerOrdersInTransit}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  in transit
                </div>
              </div>
              <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#2F6B3A" }}>
                  {buyerCompletedCount}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  completed
                </div>
              </div>
              <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                  {buyerActiveOrdersCount}
                </div>
                <div className="text-xs" style={{ color: SLATE }}>
                  active orders
                </div>
              </div>
            </div>

            <div className="grid sm:grid-cols-2 gap-6">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wide" style={{ color: SLATE }}>
                    Recent orders
                  </h3>
                  <button
                    onClick={() => setView("orders")}
                    className="text-xs font-medium underline"
                    style={{ color: SLATE }}
                  >
                    View all →
                  </button>
                </div>
                {myOrders.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    No orders yet. Anything you buy will show up here.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {myOrders.slice(0, 3).map((o) => (
                      <button
                        key={o.id}
                        onClick={() => {
                          setBuyerOrderSearch(orderNumber(o.id));
                          setBuyerOrderStatusFilter("all");
                          setView("orders");
                          window.scrollTo({ top: 0, behavior: "smooth" });
                        }}
                        className="w-full text-left p-3 rounded-lg border bg-white"
                        style={{ borderColor: "#DDD8CC" }}
                      >
                        <div className="flex items-center justify-between">
                          <span
                            className="text-xs font-medium"
                            style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                          >
                            {orderNumber(o.id)}
                          </span>
                          <span
                            className="text-sm font-semibold"
                            style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                          >
                            {formatMoney(o.total, o.currency)}
                          </span>
                        </div>
                        <div className="text-xs mt-1" style={{ color: SLATE }}>
                          {new Date(o.createdAt).toLocaleDateString(undefined, {
                            year: "numeric",
                            month: "short",
                            day: "numeric",
                          })}
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wide" style={{ color: SLATE }}>
                    Recent messages
                  </h3>
                  <button
                    onClick={() => setView("messages")}
                    className="text-xs font-medium underline"
                    style={{ color: SLATE }}
                  >
                    View all →
                  </button>
                </div>
                {myThreads.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    No messages yet.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {myThreads.slice(0, 3).map((t) => {
                      const otherName = t.buyerUsername === currentUser ? t.sellerName : t.buyerName;
                      const lastMsg = t.messages[t.messages.length - 1];
                      const isUnread =
                        lastMsg &&
                        lastMsg.senderUsername !== currentUser &&
                        lastMsg.createdAt > (messageReadState[t.id] || 0);
                      return (
                        <button
                          key={t.id}
                          onClick={() => {
                            setActiveThreadId(t.id);
                            setActiveThreadOrderId(null);
                            markThreadRead(t.id);
                            setView("messages");
                          }}
                          className="w-full text-left flex items-center gap-2 p-3 rounded-lg border bg-white"
                          style={{ borderColor: isUnread ? MARIGOLD : "#DDD8CC" }}
                        >
                          <span className="text-xl shrink-0">{t.listingEmoji}</span>
                          <div className="min-w-0 flex-1">
                            <div className="truncate" style={{ color: INK, fontWeight: isUnread ? 700 : 500 }}>
                              {otherName}
                            </div>
                            <div className="text-xs truncate" style={{ color: SLATE }}>
                              {lastMsg ? (lastMsg.type === "offer" ? `Offer: ${formatMoney(lastMsg.amount, "NGN")}` : lastMsg.text) : ""}
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {recentlyViewedIds.length > 0 && (
              <div className="mt-6">
                <h3 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: SLATE }}>
                  Recently viewed
                </h3>
                <div className="flex gap-3 overflow-x-auto pb-1">
                  {recentlyViewedIds
                    .map((id) => listings.find((l) => l.id === id))
                    .filter(Boolean)
                    .map((l) => (
                      <button
                        key={l.id}
                        onClick={() => {
                          setSelected(l);
                          setView("browse");
                        }}
                        className="w-32 shrink-0 text-left rounded-lg border bg-white overflow-hidden"
                        style={{ borderColor: "#DDD8CC" }}
                      >
                        {l.images && l.images.length > 0 ? (
                          <img src={l.images[0]} alt={l.title} className="w-full h-24 object-cover" />
                        ) : (
                          <div className="w-full h-24 flex items-center justify-center text-3xl" style={{ backgroundColor: CANVAS }}>
                            {l.emoji}
                          </div>
                        )}
                        <div className="p-2">
                          <div className="text-xs truncate" style={{ color: INK }}>
                            {l.title}
                          </div>
                          <div
                            className="text-xs font-semibold"
                            style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                          >
                            {formatMoney(l.price, l.currency)}
                          </div>
                        </div>
                      </button>
                    ))}
                </div>
              </div>
            )}

            {myPaymentMethods.length > 0 && (
              <div className="mt-6">
                <h3 className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: SLATE }}>
                  Payment methods used
                </h3>
                <div className="space-y-2">
                  {myPaymentMethods.map((m, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3 rounded-lg border bg-white"
                      style={{ borderColor: "#DDD8CC" }}
                    >
                      <span className="text-sm" style={{ color: INK }}>
                        {paymentMethodLabel(m)}
                      </span>
                      <span className="text-xs" style={{ color: SLATE }}>
                        Last used{" "}
                        {new Date(m.lastUsedAt).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}
                      </span>
                    </div>
                  ))}
                </div>
                <p className="text-xs mt-2" style={{ color: SLATE }}>
                  Shown for your reference only — payments are handled securely by Paystack, and Stallyard never sees or stores full card numbers.
                </p>
              </div>
            )}
          </div>
        )}

        {view === "orders" && (
          <div>
            <h2 className="text-2xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Your orders
            </h2>
            {!currentUser ? (
              <p className="text-sm mt-2" style={{ color: SLATE }}>
                Log in to see your order history.
              </p>
            ) : myOrders.length === 0 ? (
              <p className="text-sm mt-2" style={{ color: SLATE }}>
                No orders yet. Anything you buy will show up here.
              </p>
            ) : (
              <div>
                <div className="grid grid-cols-2 gap-3 mt-4 mb-3">
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                      {buyerActiveOrdersCount}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      active orders
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: SAGE }}>
                      {formatMoney(buyerTotalSpent, "NGN")}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      total spent ({buyerSpentOrderCount} order{buyerSpentOrderCount === 1 ? "" : "s"})
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#3B6E8F" }}>
                      {buyerOrdersWaitingToShip}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      waiting to ship
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#6B8F71" }}>
                      {buyerOrdersInTransit}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      in transit
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: "#2F6B3A" }}>
                      {buyerCompletedCount}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      completed
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-2xl font-semibold" style={{ fontFamily: "'IBM Plex Mono', monospace", color: BERRY }}>
                      {buyerActiveReturnsDisputes}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      returns/disputes
                    </div>
                  </div>
                </div>
                <div className="flex flex-col sm:flex-row gap-3 mb-4">
                  <label className="flex-1">
                    <span className="sr-only">Search your orders</span>
                    <input
                      type="search"
                      value={buyerOrderSearch}
                      onChange={(e) => setBuyerOrderSearch(e.target.value)}
                      placeholder="Search order, item, seller or tracking number"
                      className="w-full px-3 py-2 rounded-lg border bg-white outline-none text-sm"
                      style={{ borderColor: "#DDD8CC", color: INK }}
                    />
                  </label>
                  <label>
                    <span className="sr-only">Filter orders by status</span>
                    <select
                      value={buyerOrderStatusFilter}
                      onChange={(e) => setBuyerOrderStatusFilter(e.target.value)}
                      className="w-full sm:w-48 px-3 py-2 rounded-lg border bg-white outline-none text-sm"
                      style={{ borderColor: "#DDD8CC", color: INK }}
                    >
                      <option value="all">All orders</option>
                      <option value="active">Active</option>
                      <option value="preparing">Preparing</option>
                      <option value="shipped">Shipped</option>
                      <option value="delivered">Delivered</option>
                      <option value="completed">Completed</option>
                      <option value="returned">Returned</option>
                      <option value="refunded">Refunded</option>
                      <option value="disputed">Disputed</option>
                    </select>
                  </label>
                </div>
                {(buyerOrderSearch || buyerOrderStatusFilter !== "all") && (
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <p className="text-xs" style={{ color: SLATE }}>
                      {filteredBuyerOrders.length} matching order{filteredBuyerOrders.length === 1 ? "" : "s"}
                    </p>
                    <button
                      onClick={() => { setBuyerOrderSearch(""); setBuyerOrderStatusFilter("all"); }}
                      className="text-xs font-medium underline"
                      style={{ color: SLATE }}
                    >
                      Clear search and filter
                    </button>
                  </div>
                )}
                <div className="space-y-4">
                {filteredBuyerOrders.length === 0 ? (
                  <div className="p-6 rounded-lg border bg-white text-center" style={{ borderColor: "#DDD8CC" }}>
                    <p className="text-sm font-medium" style={{ color: INK }}>No matching orders</p>
                    <p className="text-xs mt-1" style={{ color: SLATE }}>Try a different search or status filter.</p>
                  </div>
                ) : filteredBuyerOrders.map((o) => (
                  <div key={o.id} className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="flex items-center justify-between mb-1">
                      <span
                        className="text-xs font-medium"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                      >
                        {orderNumber(o.id)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs" style={{ color: SLATE }}>
                        {new Date(o.createdAt).toLocaleDateString(undefined, {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                        })}
                      </span>
                      <span
                        className="text-sm font-semibold"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                      >
                        {formatMoney(o.total, o.currency)}
                      </span>
                    </div>
                    {o.shippingAddress && (
                      <div className="text-xs mb-3" style={{ color: SLATE }}>
                        Shipping to: {o.shippingAddress.street}, {o.shippingAddress.city}
                        {o.shippingAddress.state ? `, ${o.shippingAddress.state}` : ""} {o.shippingAddress.zip}
                      </div>
                    )}
                    <div className="space-y-1.5">
                      {o.items.map((item, idx) => {
                        const existingReview = getReviewFor(o.id, item.listingId);
                        const draftKey = `${o.id}-${item.id}`;
                        const draft = reviewDrafts[draftKey] || {
                          rating: existingReview?.rating || 0,
                          comment: existingReview?.comment || "",
                        };
                        return (
                          <div key={idx}>
                            <div className="flex items-center justify-between text-sm gap-2">
                              <span className="flex items-center gap-2 min-w-0" style={{ color: INK }}>
                                <span>{item.emoji}</span>
                                <span className="truncate">
                                  {item.title} {item.qty > 1 ? `×${item.qty}` : ""}
                                </span>
                              </span>
                              <span className="flex items-center gap-2 shrink-0">
                                {item.fulfillmentStatus && (
                                  <Tag color={FULFILLMENT_COLOR[item.fulfillmentStatus] || FULFILLMENT_COLOR.new}>
                                    {FULFILLMENT_LABEL[item.fulfillmentStatus] || "New"}
                                  </Tag>
                                )}
                                <span
                                  style={{ fontFamily: "'IBM Plex Mono', monospace", color: SLATE }}
                                >
                                  {formatMoney(item.price * item.qty, item.currency)}
                                </span>
                              </span>
                            </div>

                            <div className="pl-6 mt-2 mb-2">
                              <TrackingTimeline
                                item={item}
                                orderCreatedAt={o.createdAt}
                                ink={INK}
                                slate={SLATE}
                                sage={SAGE}
                                berry={BERRY}
                              />
                              <button
                                onClick={() =>
                                  startOrOpenThread(
                                    { id: item.listingId, ownerUsername: item.ownerUsername, sellerName: item.sellerName },
                                    o.id
                                  )
                                }
                                className="text-xs font-medium underline mt-2 inline-block"
                                style={{ color: INK }}
                              >
                                Message seller about this order
                              </button>
                              <button
                                onClick={() => openSellerReport(item.sellerId, item.sellerName || item.ownerUsername, o.id)}
                                className="text-xs font-medium underline mt-2 ml-3 inline-block"
                                style={{ color: BERRY }}
                              >
                                Report seller
                              </button>
                              {(item.fulfillmentStatus === "shipped" || item.fulfillmentStatus === "delivered") && item.trackingNumber && (
                                <div className="text-xs mt-2" style={{ color: SLATE }}>
                                  {item.carrier ? `${item.carrier} tracking: ` : "Tracking: "}
                                  <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                                    {item.trackingNumber}
                                  </span>{" "}
                                  <a
                                    href={buildTrackingUrl(item.trackingNumber)}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="underline font-medium"
                                    style={{ color: MARIGOLD }}
                                  >
                                    Track package →
                                  </a>
                                </div>
                              )}
                              {item.estimatedDeliveryStart && (
                                <div className="mt-2 p-2 rounded-lg border text-xs" style={{ borderColor: MARIGOLD, backgroundColor: CANVAS }}>
                                  <span className="font-medium" style={{ color: INK }}>Estimated delivery: </span>
                                  <span style={{ color: SLATE }}>
                                    {item.estimatedDeliveryEnd && item.estimatedDeliveryEnd !== item.estimatedDeliveryStart
                                      ? `${formatDeliveryDate(item.estimatedDeliveryStart)} – ${formatDeliveryDate(item.estimatedDeliveryEnd)}`
                                      : formatDeliveryDate(item.estimatedDeliveryStart)}
                                  </span>
                                </div>
                              )}
                              {item.liveLocationEnabled && (!item.liveLocationExpiresAt || item.liveLocationExpiresAt > Date.now()) && item.liveLocationLatitude !== null && item.liveLocationLongitude !== null && (
                                <div className="mt-2 p-3 rounded-lg border text-xs" style={{ borderColor: SAGE, backgroundColor: CANVAS }}>
                                  <div className="font-medium" style={{ color: INK }}>Seller is sharing their delivery location</div>
                                  <div className="mt-1" style={{ color: SLATE }}>
                                    Last updated {item.liveLocationUpdatedAt ? new Date(item.liveLocationUpdatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "just now"}
                                    {item.liveLocationAccuracy ? ` · Accuracy about ${Math.round(item.liveLocationAccuracy)} m` : ""}
                                  </div>
                                  <a
                                    href={`https://www.google.com/maps/search/?api=1&query=${item.liveLocationLatitude},${item.liveLocationLongitude}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-block mt-2 underline font-medium"
                                    style={{ color: SAGE }}
                                  >
                                    View live location on map →
                                  </a>
                                  <div className="mt-1" style={{ color: SLATE }}>Location updates while the seller keeps Stallyard open on their phone.</div>
                                </div>
                              )}
                              {item.cancellationStatus && (
                                <div className="mt-2 p-2 rounded-lg" style={{ backgroundColor: CANVAS }}>
                                  <Tag color={item.cancellationStatus === "approved" ? SAGE : item.cancellationStatus === "denied" ? BERRY : MARIGOLD}>
                                    Cancellation {item.cancellationStatus}
                                  </Tag>
                                  {item.cancellationReason && <div className="text-xs mt-1" style={{ color: SLATE }}>Reason: {item.cancellationReason}</div>}
                                  {item.cancellationStatus === "approved" && <div className="text-xs mt-1" style={{ color: SLATE }}>Your automatic refund was processed.</div>}
                                </div>
                              )}
                              {item.fulfillmentStatus === "delivered" && item.proofOfDeliveryUrl && (
                                <div className="mt-2">
                                  <div className="text-xs mb-1" style={{ color: SLATE }}>
                                    Proof of delivery:
                                  </div>
                                  <a href={item.proofOfDeliveryUrl} target="_blank" rel="noreferrer">
                                    <img
                                      src={item.proofOfDeliveryUrl}
                                      alt="Proof of delivery"
                                      className="w-20 h-20 object-cover rounded-lg border"
                                      style={{ borderColor: "#DDD8CC" }}
                                    />
                                  </a>
                                </div>
                              )}
                              {o.paymentStatus === "held" &&
                                !["cancelled", "returned"].includes(item.fulfillmentStatus) &&
                                !["requested", "approved"].includes(item.cancellationStatus) && (
                                <div className="mt-2">
                                  {(item.deliveryToken || deliveryTokens[item.id]) ? (
                                    <div className="p-3 rounded-lg" style={{ backgroundColor: CANVAS }}>
                                      <div className="text-xs font-medium mb-1" style={{ color: INK }}>Your 10-digit delivery token</div>
                                      <div className="text-xs mb-2" style={{ color: SLATE }}>
                                        This token was created after payment. Keep it private and give it to the seller only after you receive, inspect, and accept the item.
                                      </div>
                                      <div
                                        className="text-center py-2 rounded-lg text-lg font-semibold tracking-widest"
                                        style={{ backgroundColor: "white", color: INK, fontFamily: "'IBM Plex Mono', monospace" }}
                                      >
                                        {item.deliveryToken || deliveryTokens[item.id]}
                                      </div>
                                      <button
                                        onClick={() => sendDeliveryTokenToSeller(o.id, item.id)}
                                        disabled={
                                          !!item.deliveryTokenSentAt ||
                                          sendingDeliveryTokenId === item.id
                                        }
                                        className="w-full mt-2 px-3 py-2 rounded-lg text-xs font-semibold disabled:opacity-50"
                                        style={{ backgroundColor: item.deliveryTokenSentAt ? SAGE : MARIGOLD, color: INK }}
                                      >
                                        {item.deliveryTokenSentAt
                                          ? "Token sent to seller"
                                          : sendingDeliveryTokenId === item.id
                                            ? "Sending token…"
                                            : "Send token to seller"}
                                      </button>
                                      <p className="text-xs mt-2" style={{ color: BERRY }}>
                                        The seller must also upload delivery proof and enter this token before held payment can be released.
                                      </p>
                                    </div>
                                  ) : (
                                    <button
                                      onClick={() => generateDeliveryToken(item.id)}
                                      disabled={generatingTokenKey === item.id}
                                      className="text-xs font-medium underline disabled:opacity-50"
                                      style={{ color: SLATE }}
                                    >
                                      {generatingTokenKey === item.id ? "Loading token…" : "Show my delivery token"}
                                    </button>
                                  )}
                                </div>
                              )}
                              {o.paymentStatus === "released" && (
                                <div className="mt-2">
                                  <Tag color={SAGE}>Delivery completed — payment released</Tag>
                                </div>
                              )}
                            </div>

                            {item.returnStatus && (
                              <div className="pl-6 mb-2">
                                {!item.returnStatus ? (
                                  returnDrafts[draftKey] ? (
                                    <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                                      <label className="block text-xs font-medium mb-1" style={{ color: INK }}>
                                        Reason for return
                                      </label>
                                      <select
                                        value={returnDrafts[draftKey].reason}
                                        onChange={(e) =>
                                          setReturnDrafts((d) => ({
                                            ...d,
                                            [draftKey]: { ...d[draftKey], reason: e.target.value },
                                          }))
                                        }
                                        className="w-full mb-2 px-2 py-1.5 rounded-lg border outline-none text-sm bg-white"
                                        style={{ borderColor: "#DDD8CC" }}
                                      >
                                        <option value="">Select a reason...</option>
                                        {RETURN_REASONS.map((r) => (
                                          <option key={r} value={r}>
                                            {r}
                                          </option>
                                        ))}
                                      </select>
                                      <textarea
                                        value={returnDrafts[draftKey].note}
                                        onChange={(e) =>
                                          setReturnDrafts((d) => ({
                                            ...d,
                                            [draftKey]: { ...d[draftKey], note: e.target.value },
                                          }))
                                        }
                                        placeholder="Any extra detail? (optional)"
                                        rows={2}
                                        className="w-full mb-2 px-2 py-1.5 rounded-lg border outline-none text-sm"
                                        style={{ borderColor: "#DDD8CC" }}
                                      />
                                      <div className="mb-2">
                                        <label className="block text-xs font-medium mb-1" style={{ color: INK }}>
                                          Evidence photos <span className="font-normal" style={{ color: SLATE }}>(optional)</span>
                                        </label>
                                        <div className="flex items-center gap-2 flex-wrap">
                                          {(returnDrafts[draftKey].evidenceUrls || []).map((url, idx) => (
                                            <div key={idx} className="relative">
                                              <img
                                                src={url}
                                                alt={`Evidence ${idx + 1}`}
                                                className="w-14 h-14 object-cover rounded-lg border"
                                                style={{ borderColor: "#DDD8CC" }}
                                              />
                                              <button
                                                onClick={() =>
                                                  setReturnDrafts((d) => ({
                                                    ...d,
                                                    [draftKey]: {
                                                      ...d[draftKey],
                                                      evidenceUrls: d[draftKey].evidenceUrls.filter((_, i) => i !== idx),
                                                    },
                                                  }))
                                                }
                                                className="absolute -top-1.5 -right-1.5 rounded-full bg-white border"
                                                style={{ borderColor: "#DDD8CC" }}
                                                aria-label="Remove photo"
                                              >
                                                <X size={12} style={{ color: BERRY }} />
                                              </button>
                                            </div>
                                          ))}
                                          <label
                                            className="w-14 h-14 rounded-lg border flex items-center justify-center cursor-pointer text-xs"
                                            style={{ borderColor: "#DDD8CC", color: SLATE }}
                                          >
                                            {uploadingReturnEvidenceKey === draftKey ? "…" : "+"}
                                            <input
                                              type="file"
                                              accept="image/*"
                                              onChange={(e) => handleReturnEvidenceSelect(e, draftKey)}
                                              className="hidden"
                                              disabled={uploadingReturnEvidenceKey === draftKey}
                                            />
                                          </label>
                                        </div>
                                      </div>
                                      <div className="flex items-center gap-2">
                                        <button
                                          onClick={async () => {
                                            await requestReturn(
                                              o.id,
                                              item.id,
                                              returnDrafts[draftKey].reason,
                                              returnDrafts[draftKey].note,
                                              returnDrafts[draftKey].evidenceUrls || []
                                            );
                                            setReturnDrafts((d) => {
                                              const next = { ...d };
                                              delete next[draftKey];
                                              return next;
                                            });
                                          }}
                                          className="px-3 py-1.5 rounded-lg text-xs font-medium"
                                          style={{ backgroundColor: MARIGOLD, color: INK }}
                                        >
                                          Submit request
                                        </button>
                                        <button
                                          onClick={() =>
                                            setReturnDrafts((d) => {
                                              const next = { ...d };
                                              delete next[draftKey];
                                              return next;
                                            })
                                          }
                                          className="text-xs font-medium underline"
                                          style={{ color: SLATE }}
                                        >
                                          Cancel
                                        </button>
                                      </div>
                                    </div>
                                  ) : (
                                    <button
                                      onClick={() =>
                                        setReturnDrafts((d) => ({ ...d, [draftKey]: { reason: "", note: "", evidenceUrls: [] } }))
                                      }
                                      className="text-xs font-medium underline"
                                      style={{ color: SLATE }}
                                    >
                                      Report a problem
                                    </button>
                                  )
                                ) : (
                                  <div>
                                    <div className="flex items-center gap-2 flex-wrap mb-2">
                                      <Tag color={RETURN_STATUS_COLOR[item.returnStatus]}>
                                        {RETURN_STATUS_LABEL[item.returnStatus]}
                                      </Tag>
                                      <span className="text-xs" style={{ color: SLATE }}>
                                        {item.returnReason}
                                        {item.returnNote ? ` — "${item.returnNote}"` : ""}
                                      </span>
                                    </div>
                                    {item.returnStatus === "approved" && (
                                      <div>
                                        {item.returnTrackingNumber ? (
                                          <div className="text-xs" style={{ color: SLATE }}>
                                            Return tracking:{" "}
                                            <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                                              {item.returnTrackingNumber}
                                            </span>{" "}
                                            <a
                                              href={buildTrackingUrl(item.returnTrackingNumber)}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              className="underline font-medium"
                                              style={{ color: MARIGOLD }}
                                            >
                                              Track package →
                                            </a>
                                          </div>
                                        ) : (
                                          <div className="flex items-center gap-2">
                                            <input
                                              value={returnTrackingDrafts[draftKey] ?? ""}
                                              onChange={(e) =>
                                                setReturnTrackingDrafts((d) => ({ ...d, [draftKey]: e.target.value }))
                                              }
                                              placeholder="Add tracking for your return shipment"
                                              className="flex-1 px-2 py-1 rounded-lg border outline-none text-xs"
                                              style={{ borderColor: "#DDD8CC" }}
                                            />
                                            <button
                                              onClick={async () => {
                                                await updateReturnTracking(
                                                  o.id,
                                                  item.id,
                                                  (returnTrackingDrafts[draftKey] || "").trim()
                                                );
                                                setReturnTrackingDrafts((d) => {
                                                  const next = { ...d };
                                                  delete next[draftKey];
                                                  return next;
                                                });
                                              }}
                                              className="px-2 py-1 rounded-lg text-xs font-medium"
                                              style={{ backgroundColor: MARIGOLD, color: INK }}
                                            >
                                              Save
                                            </button>
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}

                            {(item.fulfillmentStatus === "delivered" || o.paymentStatus === "released") && !["cancelled", "returned"].includes(item.fulfillmentStatus) && (
                              <div className="mt-2 mb-1 pl-6">
                                {existingReview && !reviewDrafts[draftKey] ? (
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <StarDisplay value={existingReview.rating} />
                                    {existingReview.comment && (
                                      <span className="text-xs" style={{ color: SLATE }}>
                                        "{existingReview.comment}"
                                      </span>
                                    )}
                                    <button
                                      onClick={() =>
                                        setReviewDrafts((d) => ({
                                          ...d,
                                          [draftKey]: {
                                            rating: existingReview.rating,
                                            comment: existingReview.comment,
                                          },
                                        }))
                                      }
                                      className="text-xs font-medium underline"
                                      style={{ color: SLATE }}
                                    >
                                      Edit
                                    </button>
                                  </div>
                                ) : (
                                  <div className="p-3 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                                    <StarRating
                                      value={draft.rating}
                                      onChange={(n) =>
                                        setReviewDrafts((d) => ({ ...d, [draftKey]: { ...draft, rating: n } }))
                                      }
                                    />
                                    <textarea
                                      value={draft.comment}
                                      onChange={(e) =>
                                        setReviewDrafts((d) => ({
                                          ...d,
                                          [draftKey]: { ...draft, comment: e.target.value },
                                        }))
                                      }
                                      placeholder="How was it? (optional)"
                                      rows={2}
                                      className="w-full mt-2 px-2 py-1.5 rounded-lg border outline-none text-sm"
                                      style={{ borderColor: "#DDD8CC" }}
                                    />
                                    <div className="flex items-center gap-2 mt-2">
                                      <button
                                        onClick={async () => {
                                          await submitReview(
                                            o.id,
                                            item.id,
                                            item.listingId,
                                            item.ownerUsername,
                                            draft.rating,
                                            draft.comment
                                          );
                                          setReviewDrafts((d) => {
                                            const next = { ...d };
                                            delete next[draftKey];
                                            return next;
                                          });
                                        }}
                                        className="px-3 py-1.5 rounded-lg text-xs font-medium"
                                        style={{ backgroundColor: MARIGOLD, color: INK }}
                                      >
                                        {existingReview ? "Save review" : "Leave a review"}
                                      </button>
                                      {reviewDrafts[draftKey] && existingReview && (
                                        <button
                                          onClick={() =>
                                            setReviewDrafts((d) => {
                                              const next = { ...d };
                                              delete next[draftKey];
                                              return next;
                                            })
                                          }
                                          className="text-xs font-medium underline"
                                          style={{ color: SLATE }}
                                        >
                                          Cancel
                                        </button>
                                      )}
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                    {(o.refundStatus || o.paymentStatus === "refund_pending" || o.paymentStatus === "refunded") && (
                      <RefundProgress order={o} ink={INK} slate={SLATE} sage={SAGE} berry={BERRY} marigold={MARIGOLD} canvas={CANVAS} />
                    )}
                    <div className="mt-3 pt-3 flex items-center justify-between gap-3 border-t" style={{ borderColor: "#EFEBE0" }}>
                      <div className="flex items-center gap-2">
                        {o.paymentStatus === "refunded" && <Tag color={BERRY}>Refunded</Tag>}
                        {o.paymentStatus === "refund_pending" && <Tag color={MARIGOLD}>Refund pending</Tag>}
                        {o.isDisputed && <Tag color={BERRY}>Issue reported — under review</Tag>}
                        {o.refundType === "buyer_cancellation" && o.refundAmount > 0 && (
                          <span className="text-xs" style={{ color: SLATE }}>
                            Refund {formatMoney(o.refundAmount, o.currency)} · 2% fee {formatMoney(o.cancellationFee, o.currency)}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 flex-wrap justify-end">
                        {o.paymentStatus === "held" && (
                          <span className="text-xs" style={{ color: SLATE }}>Orders cannot be cancelled after placement</span>
                        )}
                        {!o.isDisputed && o.paymentStatus === "held" &&
                          !o.items.some((item) => item.deliveryTokenSentAt || item.deliveryTokenRedeemedAt) && (
                            <button onClick={() => fileDispute(o.id)} className="text-xs font-medium underline" style={{ color: SLATE }}>
                              Report an issue
                            </button>
                          )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              </div>
            )}
          </div>
        )}

        {view === "watchlist" && (
          <div>
            <h2 className="text-2xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Watchlist
            </h2>
            {!currentUser ? (
              <p className="text-sm mt-2" style={{ color: SLATE }}>
                Log in to save items for later.
              </p>
            ) : (
              <>
                <p className="text-sm mb-6" style={{ color: SLATE }}>
                  Items you've saved. Nothing here is reserved — someone else could still buy it first.
                </p>
                {(() => {
                  const savedListings = listings.filter(
                    (l) => watchlist.includes(l.id) && l.status !== "removed"
                  );
                  return savedListings.length === 0 ? (
                    <p className="text-sm" style={{ color: SLATE }}>
                      Nothing saved yet. Tap the heart icon on any listing to save it here.
                    </p>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6">
                      {savedListings.map((l) => (
                        <PriceTagCard
                          key={l.id}
                          listing={l}
                          rating={getListingRating(l.id)}
                          isSaved={true}
                          onToggleWatchlist={toggleWatchlist}
                          onOpenStorefront={openStorefront}
                          now={nowTick}
                          onVacation={getSellerVacationInfo(l.ownerUsername)}
                          onOpen={(listing) => {
                            setActiveImg(0);
                            setSelected(listing);
                          }}
                          onAddToCart={addToCart}
                        />
                      ))}
                    </div>
                  );
                })()}
              </>
            )}
          </div>
        )}

        {view === "storefront" && (
          <div>
            {(() => {
              const seller = members.find((m) => m.username === viewingSeller);
              if (!seller) {
                return (
                  <p className="text-sm" style={{ color: SLATE }}>
                    This seller couldn't be found.
                  </p>
                );
              }
              const sellerListings = listings.filter(
                (l) => l.ownerUsername === viewingSeller && l.status === "active"
              );
              const sellerRating = getSellerRating(viewingSeller);
              const reputation = getSellerReputation(viewingSeller);
              const followerCount = follows.filter((f) => f.followedUsername === viewingSeller).length;
              const isFollowing = follows.some(
                (f) => f.followerUsername === currentUser && f.followedUsername === viewingSeller
              );
              const completedSalesCount = sellerSalesCounts[viewingSeller];
              const isOwnStorefrontHeader = currentUser === viewingSeller;
              return (
                <>
                  <div className="flex items-start justify-between flex-wrap gap-4 mb-4">
                    <div className="flex items-start gap-4">
                      {seller.avatarUrl ? (
                        <img
                          src={seller.avatarUrl}
                          alt={seller.displayName}
                          className="w-16 h-16 rounded-full object-cover shrink-0"
                        />
                      ) : (
                        <div
                          className="w-16 h-16 rounded-full flex items-center justify-center text-xl font-semibold shrink-0"
                          style={{ backgroundColor: "#F1EFE7", color: INK }}
                        >
                          {seller.displayName?.[0]?.toUpperCase() || "?"}
                        </div>
                      )}
                      <div>
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <h2 className="text-2xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                            {seller.displayName}
                          </h2>
                          {seller.isAdmin && <Tag color={MARIGOLD}>Admin</Tag>}
                          {seller.isVerified && <Tag color={SAGE}>Identity verified</Tag>}
                          {seller.isEmailVerified && <Tag color={SAGE}>✓ Email verified</Tag>}
                          {seller.isPhoneVerified && <Tag color={SAGE}>✓ Phone verified</Tag>}
                          {seller.vacationMode && <Tag color={MARIGOLD}>🌴 On vacation</Tag>}
                          {reputation && (
                            <Tag color={reputation.positivePct >= 90 ? SAGE : reputation.positivePct >= 70 ? MARIGOLD : BERRY}>
                              {reputation.positivePct}% positive
                            </Tag>
                          )}
                        </div>
                        <p className="text-sm" style={{ color: SLATE }}>
                          Member since{" "}
                          {new Date(seller.joinedAt).toLocaleDateString(undefined, {
                            year: "numeric",
                            month: "long",
                          })}
                          {seller.officeLocation ? ` · ${seller.officeLocation}` : ""}
                          {reputation && ` · ${reputation.count} rating${reputation.count !== 1 ? "s" : ""}`}
                          {` · ${followerCount} follower${followerCount !== 1 ? "s" : ""}`}
                        </p>
                        {isOwnStorefrontHeader && (
                          <label
                            className="inline-block mt-2 text-xs font-medium underline cursor-pointer"
                            style={{ color: INK }}
                          >
                            {uploadingAvatar ? "Uploading…" : "Change photo"}
                            <input
                              type="file"
                              accept="image/*"
                              onChange={handleAvatarSelect}
                              className="hidden"
                              disabled={uploadingAvatar}
                            />
                          </label>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                    {currentUser !== viewingSeller && (
                      <button
                        onClick={() => toggleFollow(viewingSeller)}
                        className="px-4 py-2 rounded-lg text-sm font-medium border"
                        style={
                          isFollowing
                            ? { borderColor: "#DDD8CC", color: SLATE, backgroundColor: "white" }
                            : { borderColor: INK, backgroundColor: INK, color: "white" }
                        }
                      >
                        {isFollowing ? "Following" : "Follow"}
                      </button>
                    )}
                    <button
                      onClick={() => startOrOpenThread(sellerListings[0] || { ownerUsername: viewingSeller, sellerName: seller.displayName, id: null })}
                      disabled={sellerListings.length === 0}
                      className="px-4 py-2 rounded-lg text-sm font-medium border disabled:opacity-40"
                      style={{ borderColor: "#DDD8CC", color: SLATE }}
                    >
                      Message seller
                    </button>
                    {currentUser !== viewingSeller && (
                      <button
                        onClick={() => openSellerReport(seller.backendId, seller.displayName)}
                        className="px-4 py-2 rounded-lg text-sm font-medium border"
                        style={{ borderColor: BERRY, color: BERRY }}
                      >
                        Report seller
                      </button>
                    )}
                    </div>
                  </div>

                  {isOwnStorefrontHeader && editingStoreProfile ? (
                    <div className="mb-6 p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                      <label className="block text-xs font-medium mb-1" style={{ color: INK }}>
                        Store description
                      </label>
                      <textarea
                        value={storeProfileDraft.storeBio}
                        onChange={(e) => setStoreProfileDraft((d) => ({ ...d, storeBio: e.target.value }))}
                        placeholder="Tell buyers about your store..."
                        rows={3}
                        className="w-full mb-3 px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <label className="block text-xs font-medium mb-1" style={{ color: INK }}>
                        Store policies
                      </label>
                      <textarea
                        value={storeProfileDraft.storePolicies}
                        onChange={(e) => setStoreProfileDraft((d) => ({ ...d, storePolicies: e.target.value }))}
                        placeholder="Shipping times, returns, general terms..."
                        rows={3}
                        className="w-full mb-3 px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <div className="flex items-center gap-3">
                        <button
                          onClick={saveStoreProfile}
                          className="px-4 py-2 rounded-lg text-sm font-medium"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          Save
                        </button>
                        <button
                          onClick={() => setEditingStoreProfile(false)}
                          className="text-sm font-medium underline"
                          style={{ color: SLATE }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    (seller.storeBio || seller.storePolicies || isOwnStorefrontHeader) && (
                      <div className="mb-6 p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                        {seller.storeBio && (
                          <p className="text-sm mb-2" style={{ color: INK }}>
                            {seller.storeBio}
                          </p>
                        )}
                        {seller.storePolicies && (
                          <div>
                            <div className="text-xs font-medium mb-1" style={{ color: SLATE }}>
                              Store policies
                            </div>
                            <p className="text-sm" style={{ color: INK }}>
                              {seller.storePolicies}
                            </p>
                          </div>
                        )}
                        {isOwnStorefrontHeader && (
                          <button
                            onClick={() => {
                              setStoreProfileDraft({
                                storeBio: seller.storeBio || "",
                                storePolicies: seller.storePolicies || "",
                              });
                              setEditingStoreProfile(true);
                            }}
                            className="text-xs font-medium underline mt-2"
                            style={{ color: INK }}
                          >
                            {seller.storeBio || seller.storePolicies ? "Edit store profile" : "Add store description & policies"}
                          </button>
                        )}
                      </div>
                    )
                  )}

                  {seller.vacationMode && (
                    <div
                      className="mb-6 p-4 rounded-lg border"
                      style={{ borderColor: MARIGOLD, backgroundColor: "#FBF0DC" }}
                    >
                      <p className="text-sm" style={{ color: INK }}>
                        🌴 This seller is currently on vacation
                        {seller.vacationReturnDate
                          ? ` and will be back on ${new Date(seller.vacationReturnDate).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })}`
                          : ""}
                        . {seller.vacationMessage || "Orders placed now may ship later than usual."}
                      </p>
                    </div>
                  )}

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8 max-w-lg">
                    <div>
                      <div
                        className="text-2xl font-semibold"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                      >
                        {sellerListings.length}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        active listings
                      </div>
                    </div>
                    <div>
                      <div
                        className="text-2xl font-semibold"
                        style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                      >
                        {completedSalesCount === undefined ? "…" : completedSalesCount}
                      </div>
                      <div className="text-xs" style={{ color: SLATE }}>
                        completed sales
                      </div>
                    </div>
                    <div>
                      {reputation ? (
                        <>
                          <div
                            className="text-2xl font-semibold"
                            style={{
                              fontFamily: "'IBM Plex Mono', monospace",
                              color: reputation.positivePct >= 90 ? SAGE : reputation.positivePct >= 70 ? MARIGOLD : BERRY,
                            }}
                          >
                            {reputation.positivePct}%
                          </div>
                          <div className="text-xs" style={{ color: SLATE }}>
                            positive ({reputation.count})
                          </div>
                        </>
                      ) : (
                        <div className="text-xs" style={{ color: SLATE }}>
                          No ratings yet
                        </div>
                      )}
                    </div>
                    <div>
                      {sellerRating ? (
                        <>
                          <div className="flex items-center gap-1">
                            <StarDisplay value={sellerRating.avg} />
                          </div>
                          <div className="text-xs" style={{ color: SLATE }}>
                            {sellerRating.avg.toFixed(1)} avg
                          </div>
                        </>
                      ) : (
                        <div className="text-xs" style={{ color: SLATE }}>
                          No reviews yet
                        </div>
                      )}
                    </div>
                  </div>

                  {(() => {
                    const sellerReviews = reviews
                      .filter((r) => r.sellerUsername === viewingSeller)
                      .sort((a, b) => b.createdAt - a.createdAt);
                    const isOwnStorefront = currentUser === viewingSeller;
                    if (sellerReviews.length === 0) return null;
                    return (
                      <div className="mb-8">
                        <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                          Reviews ({sellerReviews.length})
                        </h3>
                        <div className="space-y-3">
                          {sellerReviews.map((r) => (
                            <div key={r.id} className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                              <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
                                <span className="text-sm font-medium" style={{ color: INK }}>
                                  {r.buyerName}
                                </span>
                                <span className="text-xs" style={{ color: SLATE }}>
                                  {new Date(r.createdAt).toLocaleDateString(undefined, {
                                    year: "numeric",
                                    month: "short",
                                    day: "numeric",
                                  })}
                                </span>
                              </div>
                              <StarDisplay value={r.rating} />
                              {r.comment && (
                                <p className="text-sm mt-2" style={{ color: INK }}>
                                  {r.comment}
                                </p>
                              )}
                              {r.sellerResponse && (
                                <div className="mt-3 p-3 rounded-lg" style={{ backgroundColor: CANVAS }}>
                                  <div className="text-xs font-medium mb-1" style={{ color: INK }}>
                                    Seller response
                                  </div>
                                  <p className="text-sm" style={{ color: INK }}>
                                    {r.sellerResponse}
                                  </p>
                                </div>
                              )}
                              {isOwnStorefront && !r.sellerResponse && (
                                <div className="mt-3">
                                  {reviewResponseDrafts[r.id] !== undefined ? (
                                    <div>
                                      <textarea
                                        value={reviewResponseDrafts[r.id]}
                                        onChange={(e) =>
                                          setReviewResponseDrafts((d) => ({ ...d, [r.id]: e.target.value }))
                                        }
                                        placeholder="Write a response..."
                                        rows={2}
                                        className="w-full mb-2 px-2 py-1.5 rounded-lg border outline-none text-sm"
                                        style={{ borderColor: "#DDD8CC" }}
                                      />
                                      <div className="flex items-center gap-3">
                                        <button
                                          onClick={() => respondToReview(r.id, reviewResponseDrafts[r.id])}
                                          className="text-xs font-medium underline"
                                          style={{ color: SAGE }}
                                        >
                                          Post response
                                        </button>
                                        <button
                                          onClick={() =>
                                            setReviewResponseDrafts((d) => {
                                              const next = { ...d };
                                              delete next[r.id];
                                              return next;
                                            })
                                          }
                                          className="text-xs font-medium underline"
                                          style={{ color: SLATE }}
                                        >
                                          Cancel
                                        </button>
                                      </div>
                                    </div>
                                  ) : (
                                    <button
                                      onClick={() => setReviewResponseDrafts((d) => ({ ...d, [r.id]: "" }))}
                                      className="text-xs font-medium underline"
                                      style={{ color: SLATE }}
                                    >
                                      Respond
                                    </button>
                                  )}
                                </div>
                              )}
                              {!isOwnStorefront && currentUser && (
                                <button
                                  onClick={() => {
                                    setReportReviewId(r.id);
                                    setReviewReportReasonDraft("");
                                  }}
                                  className="text-xs font-medium underline mt-3 flex items-center gap-1"
                                  style={{ color: SLATE }}
                                >
                                  <Flag size={10} />
                                  Report
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                    Listings
                  </h3>
                  {sellerListings.length === 0 ? (
                    <p className="text-sm" style={{ color: SLATE }}>
                      This seller has no active listings right now.
                    </p>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6">
                      {sellerListings.map((l) => (
                        <PriceTagCard
                          key={l.id}
                          listing={l}
                          rating={getListingRating(l.id)}
                          isSaved={watchlist.includes(l.id)}
                          onToggleWatchlist={toggleWatchlist}
                          onOpenStorefront={openStorefront}
                          now={nowTick}
                          onVacation={getSellerVacationInfo(l.ownerUsername)}
                          onOpen={(listing) => {
                            setActiveImg(0);
                            setSelected(listing);
                          }}
                          onAddToCart={addToCart}
                        />
                      ))}
                    </div>
                  )}
                </>
              );
            })()}
          </div>
        )}

        {view === "wallet" && (
          <div className="max-w-2xl">
            <h2 className="text-2xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Wallet
            </h2>
            {!currentUser ? (
              <p className="text-sm mt-2" style={{ color: SLATE }}>
                Log in to see your balance.
              </p>
            ) : (
              <>
                <p className="text-sm mb-6" style={{ color: SLATE }}>
                  Funds from your sales, tracked through the marketplace's escrow status. This isn't a real bank
                  balance — it reflects what you're owed based on order status set by the admin.
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                  <div className="p-4 rounded-lg border bg-white" style={{ borderColor: SAGE }}>
                    <div className="text-xs uppercase tracking-wide mb-1" style={{ color: SLATE }}>
                      Available
                    </div>
                    <div
                      className="text-2xl font-semibold"
                      style={{ fontFamily: "'IBM Plex Mono', monospace", color: SAGE }}
                    >
                      {formatMoney(walletNetAvailable, "NGN")}
                    </div>
                  </div>
                  <div className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-xs uppercase tracking-wide mb-1" style={{ color: SLATE }}>
                      Pending (held)
                    </div>
                    <div
                      className="text-2xl font-semibold"
                      style={{ fontFamily: "'IBM Plex Mono', monospace", color: MARIGOLD }}
                    >
                      {formatMoney(walletHeld, "NGN")}
                    </div>
                  </div>
                  <div className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-xs uppercase tracking-wide mb-1" style={{ color: SLATE }}>
                      Paid out
                    </div>
                    <div
                      className="text-2xl font-semibold"
                      style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                    >
                      {formatMoney(withdrawalsPaidTotal, "NGN")}
                    </div>
                  </div>
                  <div className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                    <div className="text-xs uppercase tracking-wide mb-1" style={{ color: SLATE }}>
                      Refunded / voided
                    </div>
                    <div
                      className="text-2xl font-semibold"
                      style={{ fontFamily: "'IBM Plex Mono', monospace", color: BERRY }}
                    >
                      {formatMoney(walletVoided, "NGN")}
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: INK }}>
                    Change password
                  </h3>
                  <p className="text-xs mb-3" style={{ color: SLATE }}>
                    You'll need your current password to set a new one.
                  </p>
                  <div className="flex flex-wrap gap-2 mb-2">
                    <input
                      type="password"
                      value={changePasswordForm.current}
                      onChange={(e) => setChangePasswordForm((f) => ({ ...f, current: e.target.value }))}
                      placeholder="Current password"
                      className="px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <input
                      type="password"
                      value={changePasswordForm.next}
                      onChange={(e) => setChangePasswordForm((f) => ({ ...f, next: e.target.value }))}
                      placeholder="New password"
                      className="px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <input
                      type="password"
                      value={changePasswordForm.confirm}
                      onChange={(e) => setChangePasswordForm((f) => ({ ...f, confirm: e.target.value }))}
                      placeholder="Confirm new password"
                      className="px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={changePassword}
                      disabled={changingPassword}
                      className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                      style={{ backgroundColor: INK, color: "white" }}
                    >
                      {changingPassword ? "Saving..." : "Save"}
                    </button>
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold" style={{ color: INK }}>
                        Two-factor authentication
                      </h3>
                      <p className="text-xs mt-1" style={{ color: SLATE }}>
                        {currentMember?.isAdmin
                          ? currentMember?.twoFactorEnabled
                            ? "On — required for admin accounts, via your authenticator app."
                            : "Required for admin accounts — set up an authenticator app below."
                          : currentMember?.twoFactorEnabled
                          ? "On — we'll email a code each time you log in."
                          : "Off — add a one-time email code to your login."}
                      </p>
                    </div>
                    {currentMember?.isAdmin ? (
                      !currentMember?.twoFactorEnabled &&
                      !adminTotpSetup && (
                        <button
                          onClick={startAdminTotpSetup}
                          disabled={startingAdminTotpSetup}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 shrink-0"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {startingAdminTotpSetup ? "Generating..." : "Set up"}
                        </button>
                      )
                    ) : currentMember?.twoFactorEnabled ? (
                      <button
                        onClick={() => toggleTwoFactor(false)}
                        disabled={savingTwoFactorToggle}
                        className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 shrink-0"
                        style={{ borderColor: "#DDD8CC", color: SLATE, backgroundColor: "white", border: "1px solid #DDD8CC" }}
                      >
                        Turn off
                      </button>
                    ) : (
                      enable2FAStep === "idle" && (
                        <button
                          onClick={sendEnableTwoFactorCode}
                          disabled={sendingEnable2FACode}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 shrink-0"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {sendingEnable2FACode ? "Sending code..." : "Turn on"}
                        </button>
                      )
                    )}
                  </div>

                  {/* Admin: authenticator app (TOTP) setup */}
                  {currentMember?.isAdmin && !currentMember?.twoFactorEnabled && adminTotpSetup && (
                    <div className="mt-3 pt-3 border-t" style={{ borderColor: "#DDD8CC" }}>
                      <p className="text-xs mb-2" style={{ color: SLATE }}>
                        Scan this QR code with your authenticator app:
                      </p>
                      <img
                        src={adminTotpSetup.qrCodeUrl}
                        alt="Authenticator app QR code"
                        className="mb-3 rounded-lg border"
                        style={{ borderColor: "#DDD8CC", width: 160, height: 160 }}
                      />
                      <p className="text-xs mb-1" style={{ color: SLATE }}>
                        Can't scan? Enter this key manually:
                      </p>
                      <p
                        className="text-xs mb-3 px-2 py-1.5 rounded border break-all"
                        style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                      >
                        {adminTotpSetup.secret}
                      </p>
                      <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                        Then enter the 6-digit code it's showing
                      </label>
                      <input
                        type="text"
                        inputMode="numeric"
                        value={adminTotpCodeInput}
                        onChange={(e) => setAdminTotpCodeInput(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && confirmAdminTotpSetup()}
                        className="w-full px-3 py-2 rounded-lg border mb-2"
                        style={{ borderColor: "#DDD8CC" }}
                        placeholder="123456"
                      />
                      {adminTotpError && (
                        <p className="text-xs mb-2" style={{ color: "#B4432A" }}>
                          {adminTotpError}
                        </p>
                      )}
                      <div className="flex items-center gap-2">
                        <button
                          onClick={confirmAdminTotpSetup}
                          disabled={confirmingAdminTotpSetup}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {confirmingAdminTotpSetup ? "Confirming..." : "Confirm code"}
                        </button>
                        <button
                          onClick={() => {
                            setAdminTotpSetup(null);
                            setAdminTotpCodeInput("");
                            setAdminTotpError("");
                          }}
                          className="text-xs underline disabled:opacity-50"
                          style={{ color: SLATE }}
                        >
                          Start over
                        </button>
                      </div>
                    </div>
                  )}
                  {currentMember?.isAdmin && !currentMember?.twoFactorEnabled && !adminTotpSetup && adminTotpError && (
                    <p className="text-xs mt-2" style={{ color: "#B4432A" }}>
                      {adminTotpError}
                    </p>
                  )}

                  {/* Non-admin: email code flow */}
                  {!currentMember?.isAdmin && !currentMember?.twoFactorEnabled && enable2FAStep === "code" && (
                    <div className="mt-3 pt-3 border-t" style={{ borderColor: "#DDD8CC" }}>
                      <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                        Enter the 6-digit code we emailed you
                      </label>
                      <input
                        type="text"
                        inputMode="numeric"
                        value={enable2FACodeInput}
                        onChange={(e) => setEnable2FACodeInput(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && verifyEnableTwoFactorCode()}
                        className="w-full px-3 py-2 rounded-lg border mb-2"
                        style={{ borderColor: "#DDD8CC" }}
                        placeholder="123456"
                      />
                      {enable2FAError && (
                        <p className="text-xs mb-2" style={{ color: "#B4432A" }}>
                          {enable2FAError}
                        </p>
                      )}
                      <div className="flex items-center gap-2">
                        <button
                          onClick={verifyEnableTwoFactorCode}
                          disabled={verifyingEnable2FACode}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {verifyingEnable2FACode ? "Confirming..." : "Confirm code"}
                        </button>
                        <button
                          onClick={sendEnableTwoFactorCode}
                          disabled={sendingEnable2FACode}
                          className="text-xs underline disabled:opacity-50"
                          style={{ color: SLATE }}
                        >
                          Resend code
                        </button>
                      </div>
                    </div>
                  )}
                  {!currentMember?.isAdmin && !currentMember?.twoFactorEnabled && enable2FAStep === "idle" && enable2FAError && (
                    <p className="text-xs mt-2" style={{ color: "#B4432A" }}>
                      {enable2FAError}
                    </p>
                  )}
                </div>

                {savedCards.length > 0 && (
                  <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                    <h3 className="text-sm font-semibold mb-1" style={{ color: INK }}>
                      Saved cards
                    </h3>
                    <p className="text-xs mb-3" style={{ color: SLATE }}>
                      Cards you've chosen to save for one-tap checkout. Stallyard never sees or stores full card
                      numbers — this list only holds a secure token from Paystack.
                    </p>
                    <div className="space-y-2">
                      {savedCards.map((c) => (
                        <div
                          key={c.id}
                          className="flex items-center justify-between p-3 rounded-lg border"
                          style={{ borderColor: "#DDD8CC" }}
                        >
                          <div>
                            <div className="text-sm" style={{ color: INK }}>
                              {c.card_type ? c.card_type.charAt(0).toUpperCase() + c.card_type.slice(1) : "Card"}
                              {c.last4 ? ` ending in ${c.last4}` : ""}
                              {c.is_default ? " (default)" : ""}
                            </div>
                            {c.exp_month && c.exp_year && (
                              <div className="text-xs" style={{ color: SLATE }}>
                                Expires {c.exp_month}/{c.exp_year}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            {!c.is_default && (
                              <button
                                onClick={() => setDefaultSavedCard(c.id)}
                                className="text-xs font-medium underline"
                                style={{ color: SLATE }}
                              >
                                Make default
                              </button>
                            )}
                            <button
                              onClick={() => deleteSavedCard(c.id)}
                              className="text-xs font-medium underline"
                              style={{ color: BERRY }}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between mb-1">
                    <h3 className="text-sm font-semibold" style={{ color: INK }}>
                      Saved addresses
                    </h3>
                    {!addressDraft && (
                      <button
                        onClick={startNewAddress}
                        className="text-xs font-medium underline"
                        style={{ color: SLATE }}
                      >
                        Add address
                      </button>
                    )}
                  </div>
                  <p className="text-xs mb-3" style={{ color: SLATE }}>
                    Pick one at checkout instead of retyping your address every time.
                  </p>

                  {savedAddresses.length === 0 && !addressDraft && (
                    <p className="text-xs" style={{ color: SLATE }}>
                      No saved addresses yet.
                    </p>
                  )}

                  {!addressDraft && (
                    <div className="space-y-2">
                      {savedAddresses.map((a) => (
                        <div
                          key={a.id}
                          className="flex items-center justify-between p-3 rounded-lg border"
                          style={{ borderColor: "#DDD8CC" }}
                        >
                          <div>
                            {a.label && (
                              <div className="text-xs font-semibold mb-0.5" style={{ color: INK }}>
                                {a.label}
                                {a.is_default ? " (default)" : ""}
                              </div>
                            )}
                            {!a.label && a.is_default && (
                              <div className="text-xs font-semibold mb-0.5" style={{ color: INK }}>
                                Default
                              </div>
                            )}
                            <div className="text-xs" style={{ color: SLATE }}>
                              {a.street}, {a.city}
                              {a.state ? `, ${a.state}` : ""} {a.zip} {a.country}
                            </div>
                          </div>
                          <div className="flex items-center gap-3 shrink-0 pl-3">
                            {!a.is_default && (
                              <button
                                onClick={() => setDefaultSavedAddress(a.id)}
                                className="text-xs font-medium underline"
                                style={{ color: SLATE }}
                              >
                                Make default
                              </button>
                            )}
                            <button
                              onClick={() => startEditAddress(a)}
                              className="text-xs font-medium underline"
                              style={{ color: SLATE }}
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => deleteSavedAddress(a.id)}
                              className="text-xs font-medium underline"
                              style={{ color: BERRY }}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {addressDraft && (
                    <div className="p-3 rounded-lg border" style={{ borderColor: "#DDD8CC" }}>
                      <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                        Label (optional — e.g. "Home", "Work")
                      </label>
                      <input
                        value={addressDraft.label}
                        onChange={(e) => setAddressDraft({ ...addressDraft, label: e.target.value })}
                        className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-2">
                        <input value={addressDraft.fullName || ""} onChange={(e) => setAddressDraft({ ...addressDraft, fullName: e.target.value })} placeholder="Recipient full name" className="px-3 py-2 rounded-lg border outline-none text-sm" style={{ borderColor: "#DDD8CC" }} />
                        <input value={addressDraft.phone || ""} onChange={(e) => setAddressDraft({ ...addressDraft, phone: e.target.value })} placeholder="Recipient phone" className="px-3 py-2 rounded-lg border outline-none text-sm" style={{ borderColor: "#DDD8CC" }} />
                      </div>
                      <label className="block text-xs font-medium mb-1" style={{ color: SLATE }}>
                        Street
                      </label>
                      <input
                        value={addressDraft.street}
                        onChange={(e) => setAddressDraft({ ...addressDraft, street: e.target.value })}
                        className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <div className="flex gap-2 mb-2">
                        <input
                          value={addressDraft.city}
                          onChange={(e) => setAddressDraft({ ...addressDraft, city: e.target.value })}
                          placeholder="City"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <input
                          value={addressDraft.state}
                          onChange={(e) => setAddressDraft({ ...addressDraft, state: e.target.value })}
                          placeholder="State"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                      </div>
                      <textarea value={addressDraft.deliveryInstructions || ""} onChange={(e) => setAddressDraft({ ...addressDraft, deliveryInstructions: e.target.value.slice(0, 1000) })} placeholder="Private delivery instructions or landmark" rows={3} className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm" style={{ borderColor: "#DDD8CC" }} />
                      <input value={addressDraft.preferredDeliveryTime || ""} onChange={(e) => setAddressDraft({ ...addressDraft, preferredDeliveryTime: e.target.value.slice(0, 200) })} placeholder="Preferred delivery time (optional)" className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm" style={{ borderColor: "#DDD8CC" }} />
                      <div className="mb-2">
                        <label className="text-xs font-medium underline cursor-pointer" style={{ color: SLATE }}>Add private location photos ({(addressDraft.locationPhotos || []).length}/5)<input type="file" accept="image/*" multiple className="hidden" onChange={handleSavedAddressLocationPhotos} /></label>
                        <div className="flex gap-2 flex-wrap mt-2">{(addressDraft.locationPhotos || []).map((photo, index) => <div key={index} className="relative"><img src={photo} alt={`Location ${index + 1}`} className="w-14 h-14 object-cover rounded-lg border" /><button type="button" onClick={() => setAddressDraft((draft) => ({ ...draft, locationPhotos: draft.locationPhotos.filter((_, i) => i !== index) }))} className="absolute -top-1 -right-1 bg-white rounded-full border" aria-label="Remove photo"><X size={12} /></button></div>)}</div>
                      </div>
                      <div className="flex gap-2 mb-2">
                        <input
                          value={addressDraft.zip}
                          onChange={(e) => setAddressDraft({ ...addressDraft, zip: e.target.value })}
                          placeholder="Postal code"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <input
                          value="Nigeria"
                          readOnly
                          aria-label="Country"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm bg-gray-50"
                          style={{ borderColor: "#DDD8CC", color: INK }}
                        />
                      </div>
                      {addressError && (
                        <p className="text-xs mb-2" style={{ color: "#B4432A" }}>
                          {addressError}
                        </p>
                      )}
                      <div className="flex items-center gap-2">
                        <button
                          onClick={saveAddressDraft}
                          disabled={addressSaving}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {addressSaving ? "Saving..." : "Save address"}
                        </button>
                        <button
                          onClick={() => setAddressDraft(null)}
                          className="text-xs font-medium underline"
                          style={{ color: SLATE }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between mb-1">
                    <h3 className="text-sm font-semibold" style={{ color: INK }}>
                      Login history
                    </h3>
                    {loginHistory === null && (
                      <button
                        onClick={fetchLoginHistory}
                        disabled={loadingLoginHistory}
                        className="text-xs font-medium underline"
                        style={{ color: SLATE }}
                      >
                        {loadingLoginHistory ? "Loading..." : "Show"}
                      </button>
                    )}
                  </div>
                  {loginHistory === null ? (
                    <p className="text-xs" style={{ color: SLATE }}>
                      See the last 20 times this account was signed into, with device and location info.
                    </p>
                  ) : loginHistory.length === 0 ? (
                    <p className="text-xs" style={{ color: SLATE }}>
                      No login history yet.
                    </p>
                  ) : (
                    <div className="space-y-2 mt-2">
                      {loginHistory.map((h) => (
                        <div key={h.id} className="flex items-center justify-between text-xs" style={{ color: INK }}>
                          <span>
                            {describeUserAgent(h.user_agent)}
                            {h.ip ? ` · ${h.ip}` : ""}
                          </span>
                          <span style={{ color: SLATE }}>{new Date(h.created_at).toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <p className="text-xs mt-2" style={{ color: SLATE }}>
                    Don't recognize something here? Change your password above right away.
                  </p>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold" style={{ color: INK }}>
                        Sign out of other devices
                      </h3>
                      <p className="text-xs mt-1" style={{ color: SLATE }}>
                        Ends every other active session. This device stays signed in.
                      </p>
                    </div>
                    <button
                      onClick={signOutOtherDevices}
                      disabled={signingOutOtherDevices}
                      className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 shrink-0"
                      style={{ border: "1px solid #DDD8CC", color: SLATE, backgroundColor: "white" }}
                    >
                      {signingOutOtherDevices ? "Signing out..." : "Sign out others"}
                    </button>
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: INK }}>
                    Report suspicious activity
                  </h3>
                  <p className="text-xs mb-2" style={{ color: SLATE }}>
                    See something on your account that doesn't look right? Let an admin know.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <textarea
                      value={suspiciousActivityMessage}
                      onChange={(e) => setSuspiciousActivityMessage(e.target.value)}
                      placeholder="What did you notice?"
                      rows={2}
                      className="flex-1 min-w-[200px] px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={reportSuspiciousActivity}
                      disabled={submittingSuspiciousReport}
                      className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50 self-start"
                      style={{ backgroundColor: BERRY, color: "white" }}
                    >
                      {submittingSuspiciousReport ? "Sending..." : "Report"}
                    </button>
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                    Email & phone verification
                  </h3>

                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm" style={{ color: INK }}>
                      Email {currentMember?.email ? `(${currentMember.email})` : ""}
                    </span>
                    {currentMember?.isEmailVerified ? (
                      <Tag color={SAGE}>Verified</Tag>
                    ) : !accountEmailCodeSent ? (
                      <button
                        onClick={sendAccountEmailCode}
                        className="text-xs font-medium underline"
                        style={{ color: INK }}
                      >
                        Verify
                      </button>
                    ) : null}
                  </div>
                  {!currentMember?.isEmailVerified && accountEmailCodeSent && (
                    <div className="flex items-center gap-2 mt-2 mb-3">
                      <input
                        value={accountEmailCodeInput}
                        onChange={(e) => setAccountEmailCodeInput(e.target.value)}
                        placeholder="6-digit code"
                        maxLength={6}
                        className="px-3 py-2 rounded-lg border outline-none text-sm w-32 text-center"
                        style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                      />
                      <button
                        onClick={confirmAccountEmailCode}
                        disabled={verifyingAccountEmail}
                        className="px-3 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ backgroundColor: MARIGOLD, color: INK }}
                      >
                        {verifyingAccountEmail ? "Checking..." : "Confirm"}
                      </button>
                      <button
                        onClick={() => setAccountEmailCodeSent(false)}
                        className="text-xs font-medium underline"
                        style={{ color: SLATE }}
                      >
                        Cancel
                      </button>
                    </div>
                  )}

                  <div className="pt-3 mt-3" style={{ borderTop: "1px solid #EFEBE0" }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm" style={{ color: INK }}>
                        Phone {currentMember?.phone ? `(${currentMember.phone})` : ""}
                      </span>
                      {currentMember?.isPhoneVerified && <Tag color={SAGE}>Verified</Tag>}
                    </div>
                    {!currentMember?.isPhoneVerified && !accountPhoneCodeSent && (
                      <div className="flex items-center gap-2 mt-2">
                        <input
                          value={accountPhoneInput}
                          onChange={(e) => setAccountPhoneInput(e.target.value)}
                          placeholder={currentMember?.phone || "Phone number"}
                          className="px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <button
                          onClick={sendAccountPhoneCode}
                          className="px-3 py-2 rounded-lg text-sm font-medium"
                          style={{ backgroundColor: INK, color: "white" }}
                        >
                          Send code
                        </button>
                      </div>
                    )}
                    {!currentMember?.isPhoneVerified && accountPhoneCodeSent && (
                      <div className="flex items-center gap-2 mt-2">
                        <input
                          value={accountPhoneCodeInput}
                          onChange={(e) => setAccountPhoneCodeInput(e.target.value)}
                          placeholder="6-digit code"
                          maxLength={6}
                          className="px-3 py-2 rounded-lg border outline-none text-sm w-32 text-center"
                          style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                        />
                        <button
                          onClick={confirmAccountPhoneCode}
                          disabled={verifyingAccountPhone}
                          className="px-3 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {verifyingAccountPhone ? "Checking..." : "Confirm"}
                        </button>
                        <button
                          onClick={() => setAccountPhoneCodeSent(false)}
                          className="text-xs font-medium underline"
                          style={{ color: SLATE }}
                        >
                          Cancel
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-lg border bg-white mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: INK }}>
                    Payout bank details
                  </h3>
                  {pendingBankChange ? (
                    <>
                      <p className="text-xs mb-3" style={{ color: SLATE }}>
                        We emailed a code to confirm this change. Enter it below to finish updating your payout account.
                      </p>
                      <div className="flex flex-wrap gap-2 mb-2">
                        <input
                          value={bankChangeCodeInput}
                          onChange={(e) => setBankChangeCodeInput(e.target.value)}
                          placeholder="6-digit code"
                          maxLength={6}
                          className="px-3 py-2 rounded-lg border outline-none text-sm w-32 text-center"
                          style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                        />
                        <button
                          onClick={confirmBankChange}
                          disabled={bankSaving}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                          style={{ backgroundColor: MARIGOLD, color: INK }}
                        >
                          {bankSaving ? "Confirming..." : "Confirm change"}
                        </button>
                        <button
                          onClick={() => {
                            setPendingBankChange(false);
                            setBankChangeCodeInput("");
                          }}
                          className="text-xs font-medium underline"
                          style={{ color: SLATE }}
                        >
                          Cancel
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="text-xs mb-3" style={{ color: SLATE }}>
                        {currentMember?.hasBankDetails
                          ? "Your bank details are on file. Changing them requires confirming a code we'll email you."
                          : "Add your bank details before requesting a withdrawal — payouts go here automatically."}
                      </p>
                      <div className="flex flex-wrap gap-2 mb-2">
                        <select
                          value={bankForm.bankCode}
                          onFocus={loadBankList}
                          onChange={(e) => setBankForm({ ...bankForm, bankCode: e.target.value })}
                          className="px-3 py-2 rounded-lg border outline-none text-sm bg-white"
                          style={{ borderColor: "#DDD8CC", minWidth: "180px" }}
                        >
                          <option value="">Select your bank</option>
                          {bankList.map((b) => (
                            <option key={b.code} value={b.code}>
                              {b.name}
                            </option>
                          ))}
                        </select>
                        <input
                          value={bankForm.accountNumber}
                          onChange={(e) => setBankForm({ ...bankForm, accountNumber: e.target.value.replace(/\D/g, "").slice(0, 10) })}
                          placeholder="Account number"
                          inputMode="numeric"
                          maxLength={10}
                          className="px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <button
                          onClick={saveBankDetails}
                          disabled={bankSaving}
                          className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                          style={{ backgroundColor: INK, color: "white" }}
                        >
                          {bankSaving ? "Saving..." : "Save"}
                        </button>
                      </div>
                      {bankResolution.status === "checking" && <p className="text-xs mb-2" style={{ color: SLATE }}>Checking account owner with Paystack…</p>}
                      {bankResolution.accountName && (
                        <div className="mb-2 p-3 rounded-lg border" style={{ borderColor: bankResolution.nameMatches ? SAGE : BERRY, backgroundColor: bankResolution.nameMatches ? "#EDF4EE" : "#FBEAEA" }}>
                          <p className="text-xs" style={{ color: SLATE }}>Paystack-verified account owner</p>
                          <p className="font-semibold" style={{ color: INK }}>{bankResolution.accountName}</p>
                          {bankResolution.nameMatches ? <label className="flex gap-2 items-center text-xs mt-2" style={{ color: INK }}><input type="checkbox" checked={bankOwnerConfirmed} onChange={(e) => setBankOwnerConfirmed(e.target.checked)} />I confirm this bank account belongs to me.</label> : <p className="text-xs mt-1" style={{ color: BERRY }}>{bankResolution.error}</p>}
                        </div>
                      )}
                      {bankResolution.status === "error" && <p className="text-xs mb-2" style={{ color: BERRY }}>{bankResolution.error}</p>}
                    </>
                  )}
                </div>

                <div className="p-4 rounded-lg border bg-white mb-8" style={{ borderColor: "#DDD8CC" }}>
                  <h3 className="text-sm font-semibold mb-2" style={{ color: INK }}>
                    Request a withdrawal
                  </h3>
                  <div className="flex items-center gap-2 mb-2">
                    <span style={{ color: SLATE }}>₦</span>
                    <input
                      type="number"
                      min="0"
                      max={walletNetAvailable}
                      step="0.01"
                      value={withdrawAmount}
                      onChange={(e) => setWithdrawAmount(e.target.value)}
                      placeholder={walletNetAvailable.toFixed(2)}
                      className="w-32 px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={async () => {
                        await requestWithdrawal(withdrawAmount || walletNetAvailable);
                        setWithdrawAmount("");
                      }}
                      disabled={walletNetAvailable <= 0}
                      className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      Request
                    </button>
                  </div>
                  <p className="text-xs" style={{ color: SLATE }}>
                    Up to {formatMoney(walletNetAvailable, "NGN")} available. The admin marks requests as paid outside this app.
                  </p>
                </div>

                {myWithdrawals.length > 0 && (
                  <div className="mb-8">
                    <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                      Your withdrawal requests
                    </h3>
                    <div className="space-y-2">
                      {myWithdrawals.map((w) => (
                        <div
                          key={w.id}
                          className="flex items-center justify-between gap-3 p-3 rounded-lg border bg-white"
                          style={{ borderColor: "#DDD8CC" }}
                        >
                          <span className="text-xs" style={{ color: SLATE }}>
                            {new Date(w.requestedAt).toLocaleDateString(undefined, {
                              year: "numeric",
                              month: "short",
                              day: "numeric",
                            })}
                          </span>
                          <div className="flex items-center gap-3">
                            <Tag
                              color={
                                w.status === "paid" ? SAGE : w.status === "failed" ? BERRY : MARIGOLD
                              }
                            >
                              {w.status === "paid" ? "Paid" : w.status === "failed" ? "Failed" : "Processing"}
                            </Tag>
                            <span
                              className="font-medium"
                              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                            >
                              {formatMoney(w.amount)}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                  Transactions
                </h3>
                {myWalletTx.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    No wallet activity yet — it'll show up here once you make a sale.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {myWalletTx
                      .slice()
                      .sort((a, b) => b.createdAt - a.createdAt)
                      .map((t) => (
                        <div
                          key={t.key}
                          className="flex items-center justify-between gap-3 p-3 rounded-lg border bg-white"
                          style={{ borderColor: "#DDD8CC" }}
                        >
                          <div className="min-w-0">
                            <div className="text-sm truncate" style={{ color: INK }}>
                              {t.title} × {t.qty}
                              <span style={{ color: SLATE }}> — {t.buyerName}</span>
                            </div>
                            <div className="text-xs" style={{ color: SLATE }}>
                              {new Date(t.createdAt).toLocaleDateString(undefined, {
                                year: "numeric",
                                month: "short",
                                day: "numeric",
                              })}
                            </div>
                          </div>
                          <div className="flex items-center gap-3 shrink-0">
                            <Tag
                              color={
                                t.walletStatus === "released"
                                  ? SAGE
                                  : t.walletStatus === "held"
                                  ? MARIGOLD
                                  : BERRY
                              }
                            >
                              {t.walletStatus === "released"
                                ? "Available"
                                : t.walletStatus === "held"
                                ? "Held"
                                : t.walletStatus === "refunded"
                                ? "Refunded"
                                : "Voided"}
                            </Tag>
                            <span
                              className="font-medium"
                              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                            >
                              {formatMoney(t.payout)}
                            </span>
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {view === "messages" && (
          <div>
            <h2 className="text-2xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Messages
            </h2>
            {!currentUser ? (
              <p className="text-sm mt-2" style={{ color: SLATE }}>
                Log in to see your conversations.
              </p>
            ) : !activeThread ? (
              <>
                <p className="text-sm mb-6" style={{ color: SLATE }}>
                  Chat with buyers and sellers about a listing. For everyone's safety, email addresses and phone
                  numbers can't be sent here — keep contact on Stallyard.
                </p>
                {myThreads.length === 0 ? (
                  <p className="text-sm" style={{ color: SLATE }}>
                    No conversations yet. Message a seller from any listing to start one.
                  </p>
                ) : (
                  <div className="space-y-2 max-w-xl">
                    {myThreads.map((t) => {
                      const otherName = t.buyerUsername === currentUser ? t.sellerName : t.buyerName;
                      const lastMsg = t.messages[t.messages.length - 1];
                      const isUnread =
                        lastMsg &&
                        lastMsg.senderUsername !== currentUser &&
                        lastMsg.createdAt > (messageReadState[t.id] || 0);
                      return (
                        <button
                          key={t.id}
                          onClick={() => {
                            setActiveThreadId(t.id);
                            setActiveThreadOrderId(null);
                            markThreadRead(t.id);
                          }}
                          className="w-full text-left flex items-center gap-3 p-3 rounded-lg border bg-white"
                          style={{ borderColor: isUnread ? MARIGOLD : "#DDD8CC" }}
                        >
                          {isUnread && (
                            <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: MARIGOLD }} />
                          )}
                          <span className="text-2xl shrink-0">{t.listingEmoji}</span>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between gap-2">
                              <span className="truncate" style={{ color: INK, fontWeight: isUnread ? 700 : 500 }}>
                                {otherName}
                              </span>
                              <span className="text-xs shrink-0" style={{ color: SLATE }}>
                                {new Date(t.updatedAt).toLocaleDateString(undefined, {
                                  month: "short",
                                  day: "numeric",
                                })}
                              </span>
                            </div>
                            <div className="text-xs truncate" style={{ color: SLATE }}>
                              {t.listingTitle}
                              {lastMsg
                                ? ` — ${lastMsg.type === "offer" ? `Offer: ${formatMoney(lastMsg.amount, "NGN")}` : lastMsg.text}`
                                : ""}
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </>
            ) : (
              <div className="max-w-xl">
                <button
                  onClick={() => {
                    setActiveThreadId(null);
                    setActiveThreadOrderId(null);
                    setMessageError("");
                  }}
                  className="text-xs font-medium underline mb-3"
                  style={{ color: SLATE }}
                >
                  ← Back to conversations
                </button>
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-2xl">{activeThread.listingEmoji}</span>
                  <div>
                    <div className="font-medium" style={{ color: INK }}>
                      {activeThread.buyerUsername === currentUser
                        ? activeThread.sellerName
                        : activeThread.buyerName}
                    </div>
                    <div className="text-xs" style={{ color: SLATE }}>
                      About: {activeThread.listingTitle}
                    </div>
                  </div>
                  {activeThread.buyerUsername === currentUser && (
                    <button
                      onClick={() => {
                        const seller = members.find((member) => member.username === activeThread.sellerUsername);
                        openSellerReport(seller?.backendId, activeThread.sellerName || activeThread.sellerUsername, activeThreadOrderId || null);
                      }}
                      className="ml-auto text-xs font-medium underline"
                      style={{ color: BERRY }}
                    >
                      Report seller
                    </button>
                  )}
                </div>

                <div
                  className="rounded-lg border bg-white p-4 mb-3 space-y-3 overflow-y-auto"
                  style={{ borderColor: "#DDD8CC", maxHeight: "50vh", minHeight: "200px" }}
                >
                  {activeThread.messages.length === 0 && (
                    <p className="text-sm" style={{ color: SLATE }}>
                      Say hello — no messages yet.
                    </p>
                  )}
                  {activeThread.messages.map((m) => {
                    const mine = m.senderUsername === currentUser;
                    if (m.type === "offer") {
                      const isBuyer = activeThread.buyerUsername === currentUser;
                      const listingForOffer = listings.find((l) => l.id === activeThread.listingId);
                      return (
                        <div key={m.id} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                          <div
                            className="max-w-[75%] px-3 py-2.5 rounded-lg text-sm border"
                            style={{
                              backgroundColor: mine ? "#FBF0DC" : "white",
                              borderColor: MARIGOLD,
                              color: INK,
                            }}
                          >
                            <div className="font-medium mb-1">
                              Offer: {formatMoney(m.amount)}
                            </div>
                            {m.status === "pending" && !mine && (
                              <div className="flex items-center gap-3 mt-1">
                                <button
                                  onClick={() => respondToOffer(activeThread.id, m.id, "accepted")}
                                  className="text-xs font-medium underline"
                                  style={{ color: SAGE }}
                                >
                                  Accept
                                </button>
                                <button
                                  onClick={() => respondToOffer(activeThread.id, m.id, "declined")}
                                  className="text-xs font-medium underline"
                                  style={{ color: BERRY }}
                                >
                                  Decline
                                </button>
                              </div>
                            )}
                            {m.status === "pending" && mine && (
                              <div className="text-xs" style={{ color: SLATE }}>
                                Waiting for a response...
                              </div>
                            )}
                            {m.status === "accepted" && (
                              <div className="flex items-center gap-2 mt-1 flex-wrap">
                                <Tag color={SAGE}>Accepted</Tag>
                                {isBuyer && listingForOffer && (
                                  <button
                                    onClick={() => addToCartAtPrice(listingForOffer, m.amount)}
                                    className="text-xs font-medium underline"
                                    style={{ color: INK }}
                                  >
                                    Add to cart at {formatMoney(m.amount)}
                                  </button>
                                )}
                              </div>
                            )}
                            {m.status === "declined" && (
                              <Tag color={BERRY}>Declined</Tag>
                            )}
                            <div className="text-[10px] mt-1" style={{ color: SLATE }}>
                              {new Date(m.createdAt).toLocaleTimeString(undefined, {
                                hour: "numeric",
                                minute: "2-digit",
                              })}
                            </div>
                          </div>
                        </div>
                      );
                    }
                    return (
                      <div key={m.id} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                        <div
                          className="max-w-[75%] px-3 py-2 rounded-lg text-sm"
                          style={{
                            backgroundColor: mine ? INK : "#F1EFE7",
                            color: mine ? "white" : INK,
                          }}
                        >
                          {m.imageUrl && (
                            <a href={m.imageUrl} target="_blank" rel="noreferrer">
                              <img
                                src={m.imageUrl}
                                alt="Attachment"
                                className="rounded-lg mb-1 max-w-full"
                                style={{ maxHeight: "200px" }}
                              />
                            </a>
                          )}
                          {m.text}
                          <div
                            className="flex items-center gap-2 text-[10px] mt-1"
                            style={{ color: mine ? "#C9CCD3" : SLATE }}
                          >
                            {new Date(m.createdAt).toLocaleTimeString(undefined, {
                              hour: "numeric",
                              minute: "2-digit",
                            })}
                            {!mine && (
                              <button
                                onClick={() => {
                                  setReportMessageId(m.id);
                                  setReportReasonDraft("");
                                }}
                                className="underline flex items-center gap-0.5"
                                style={{ color: mine ? "#C9CCD3" : SLATE }}
                                title="Report this message"
                              >
                                <Flag size={10} />
                                Report
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {messageError && (
                  <p className="text-xs mb-2" style={{ color: BERRY }}>
                    {messageError}
                  </p>
                )}

                {offerModalOpen && (
                  <div className="flex items-center gap-2 mb-2 p-2 rounded-lg border" style={{ borderColor: MARIGOLD }}>
                    <span style={{ color: SLATE }}>₦</span>
                    <input
                      type="number"
                      min="0"
                      step="0.01"
                      value={offerAmount}
                      onChange={(e) => setOfferAmount(e.target.value)}
                      placeholder="Your offer"
                      autoFocus
                      className="flex-1 px-2 py-1.5 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={async () => {
                        await sendOffer(activeThread.id, offerAmount);
                        setOfferAmount("");
                        setOfferModalOpen(false);
                      }}
                      className="px-3 py-1.5 rounded-lg text-sm font-medium"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      Send offer
                    </button>
                    <button
                      onClick={() => {
                        setOfferModalOpen(false);
                        setOfferAmount("");
                      }}
                      aria-label="Cancel offer"
                    >
                      <X size={16} style={{ color: SLATE }} />
                    </button>
                  </div>
                )}

                <div className="flex items-center gap-2">
                  {!offerModalOpen && (
                    <button
                      type="button"
                      onClick={() => setOfferModalOpen(true)}
                      className="p-2.5 rounded-lg border shrink-0"
                      style={{ borderColor: MARIGOLD, color: MARIGOLD }}
                      aria-label="Make an offer"
                      title="Make an offer"
                    >
                      ₦
                    </button>
                  )}
                  <label
                    className="p-2.5 rounded-lg border shrink-0 cursor-pointer flex items-center justify-center"
                    style={{ borderColor: "#DDD8CC", color: SLATE }}
                    title="Attach a photo"
                  >
                    <ImageIcon size={16} />
                    <input
                      type="file"
                      accept="image/*"
                      onChange={(e) => handleMessagePhotoSelect(e, activeThread.id)}
                      className="hidden"
                      disabled={uploadingMessagePhoto}
                    />
                  </label>
                  <input
                    value={messageInput}
                    onChange={(e) => {
                      setMessageInput(e.target.value);
                      if (messageError) setMessageError("");
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") sendMessage(activeThread.id, messageInput);
                    }}
                    placeholder="Type a message..."
                    className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                    style={{ borderColor: "#DDD8CC" }}
                  />
                  <button
                    type="button"
                    onClick={() => sendMessage(activeThread.id, messageInput)}
                    className="p-2.5 rounded-lg"
                    style={{ backgroundColor: MARIGOLD, color: INK }}
                    aria-label="Send"
                  >
                    <Send size={16} />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {view === "help" && activeTicketId && (
          <div className="max-w-2xl">
            <button
              onClick={() => {
                setActiveTicketId(null);
                setTicketMessages([]);
              }}
              className="text-sm font-medium underline mb-4"
              style={{ color: SLATE }}
            >
              ← Back to Help center
            </button>
            {(() => {
              const ticket =
                (currentMember?.isAdmin ? adminTickets : myTickets).find((t) => t.id === activeTicketId) || null;
              return (
                <>
                  <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
                    <h2 className="text-2xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                      {ticket?.subject || "Ticket"}
                    </h2>
                    {ticket && (
                      <Tag color={ticket.status === "resolved" ? SAGE : ticket.status === "in_progress" ? MARIGOLD : SLATE}>
                        {TICKET_STATUS_LABEL[ticket.status] || ticket.status}
                      </Tag>
                    )}
                  </div>
                  {ticket && !currentMember?.isAdmin && (
                    <p className="text-xs mb-4" style={{ color: SLATE }}>
                      Opened {new Date(ticket.created_at).toLocaleDateString()}
                    </p>
                  )}
                  {ticket && currentMember?.isAdmin && (
                    <div className="flex items-center gap-2 mb-4">
                      <span className="text-xs" style={{ color: SLATE }}>
                        From {ticket.display_name || ticket.username} · Set status:
                      </span>
                      <select
                        value={ticket.status}
                        onChange={(e) => adminUpdateTicketStatus(ticket.id, e.target.value)}
                        className="px-2 py-1 rounded-lg border outline-none text-xs bg-white"
                        style={{ borderColor: "#DDD8CC" }}
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In progress</option>
                        <option value="resolved">Resolved</option>
                      </select>
                    </div>
                  )}
                  {loadingTicketMessages ? (
                    <p className="text-sm" style={{ color: SLATE }}>
                      Loading...
                    </p>
                  ) : (
                    <div className="space-y-3 mb-4">
                      {ticketMessages.map((m) => {
                        const fromAdmin = m.is_admin;
                        return (
                          <div key={m.id} className={`flex ${fromAdmin ? "justify-start" : "justify-end"}`}>
                            <div
                              className="max-w-[80%] px-3 py-2 rounded-lg text-sm"
                              style={{ backgroundColor: fromAdmin ? "#F1EFE7" : INK, color: fromAdmin ? INK : "white" }}
                            >
                              <div className="text-xs font-medium mb-1" style={{ color: fromAdmin ? SLATE : "#C9CCD3" }}>
                                {m.display_name || m.username}
                              </div>
                              {m.body}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  <div className="flex items-center gap-2">
                    <input
                      value={newTicketMessageInput}
                      onChange={(e) => setNewTicketMessageInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && sendTicketMessage()}
                      placeholder="Write a reply..."
                      className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={sendTicketMessage}
                      disabled={sendingTicketMessage}
                      className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      Send
                    </button>
                  </div>
                </>
              );
            })()}
          </div>
        )}

        {view === "help" && !activeTicketId && (
          <div className="max-w-2xl">
            <h2 className="text-2xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Help center
            </h2>
            <p className="text-sm mb-6" style={{ color: SLATE }}>
              Articles and answers to common questions.
            </p>

            <div className="mb-8">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold" style={{ color: INK }}>
                  Contact support
                </h3>
                {currentUser && (
                  <button
                    onClick={() => setShowNewTicketForm((v) => !v)}
                    className="text-xs font-medium underline"
                    style={{ color: INK }}
                  >
                    {showNewTicketForm ? "Cancel" : "+ New ticket"}
                  </button>
                )}
              </div>
              {!currentUser ? (
                <p className="text-sm" style={{ color: SLATE }}>
                  <button onClick={() => setView("signin")} className="underline" style={{ color: INK }}>
                    Log in
                  </button>{" "}
                  to contact support.
                </p>
              ) : (
                <>
                  {showNewTicketForm && (
                    <div className="p-4 rounded-lg border bg-white mb-3" style={{ borderColor: "#DDD8CC" }}>
                      <input
                        value={newTicketForm.subject}
                        onChange={(e) => setNewTicketForm((f) => ({ ...f, subject: e.target.value }))}
                        placeholder="Subject"
                        className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <textarea
                        value={newTicketForm.message}
                        onChange={(e) => setNewTicketForm((f) => ({ ...f, message: e.target.value }))}
                        placeholder="Describe what's going on..."
                        rows={3}
                        className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <button
                        onClick={createSupportTicket}
                        disabled={creatingTicket}
                        className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
                        style={{ backgroundColor: MARIGOLD, color: INK }}
                      >
                        {creatingTicket ? "Submitting..." : "Submit ticket"}
                      </button>
                    </div>
                  )}
                  {myTickets.length === 0 ? (
                    !showNewTicketForm && (
                      <p className="text-sm" style={{ color: SLATE }}>
                        No tickets yet.
                      </p>
                    )
                  ) : (
                    <div className="space-y-2">
                      {myTickets.map((t) => (
                        <button
                          key={t.id}
                          onClick={() => openTicketThread(t.id)}
                          className="w-full text-left flex items-center justify-between gap-3 p-3 rounded-lg border bg-white"
                          style={{ borderColor: "#DDD8CC" }}
                        >
                          <span className="text-sm font-medium truncate" style={{ color: INK }}>
                            {t.subject}
                          </span>
                          <Tag color={t.status === "resolved" ? SAGE : t.status === "in_progress" ? MARIGOLD : SLATE}>
                            {TICKET_STATUS_LABEL[t.status] || t.status}
                          </Tag>
                        </button>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="mb-8">
              <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                Marketplace policies
              </h3>
              <div className="space-y-2">
                {POLICY_ORDER.map((cat) => (
                  <div key={cat} className="rounded-lg border bg-white overflow-hidden" style={{ borderColor: "#DDD8CC" }}>
                    <div className="px-4 py-3 flex items-center justify-between gap-3">
                      <span className="text-sm font-medium" style={{ color: INK }}>
                        {POLICY_LABELS[cat]}
                      </span>
                      {currentMember?.isAdmin && editingPolicyCategory !== cat && (
                        <button
                          onClick={() => {
                            setEditingPolicyCategory(cat);
                            setPolicyDraft(policies[cat] || "");
                          }}
                          className="text-xs font-medium underline shrink-0"
                          style={{ color: SLATE }}
                        >
                          Edit
                        </button>
                      )}
                    </div>
                    {editingPolicyCategory === cat ? (
                      <div className="px-4 pb-3">
                        <textarea
                          value={policyDraft}
                          onChange={(e) => setPolicyDraft(e.target.value)}
                          rows={4}
                          className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <div className="flex items-center gap-3">
                          <button
                            onClick={async () => {
                              await savePolicy(cat, policyDraft);
                              setEditingPolicyCategory(null);
                            }}
                            className="text-xs font-medium underline"
                            style={{ color: SAGE }}
                          >
                            Save
                          </button>
                          <button
                            onClick={() => setEditingPolicyCategory(null)}
                            className="text-xs font-medium underline"
                            style={{ color: SLATE }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      policies[cat] && (
                        <div className="px-4 pb-3 text-sm whitespace-pre-wrap" style={{ color: SLATE }}>
                          {policies[cat]}
                        </div>
                      )
                    )}
                  </div>
                ))}
              </div>
            </div>

            {content.articles.length > 0 && (
              <div className="mb-8">
                <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                  Help articles
                </h3>
                <div className="space-y-3">
                  {content.articles.map((a) => (
                    <div key={a.id} className="p-4 rounded-lg border bg-white" style={{ borderColor: "#DDD8CC" }}>
                      <h4 className="font-medium mb-1" style={{ color: INK }}>
                        {a.title}
                      </h4>
                      <p className="text-sm whitespace-pre-wrap" style={{ color: SLATE }}>
                        {a.body}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {content.faqs.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-3" style={{ color: INK }}>
                  Frequently asked questions
                </h3>
                <div className="space-y-2">
                  {content.faqs.map((f) => (
                    <div key={f.id} className="rounded-lg border bg-white overflow-hidden" style={{ borderColor: "#DDD8CC" }}>
                      <button
                        onClick={() => setOpenFaqId(openFaqId === f.id ? null : f.id)}
                        className="w-full text-left px-4 py-3 flex items-center justify-between gap-3"
                      >
                        <span className="text-sm font-medium" style={{ color: INK }}>
                          {f.question}
                        </span>
                        <span style={{ color: SLATE }}>{openFaqId === f.id ? "−" : "+"}</span>
                      </button>
                      {openFaqId === f.id && (
                        <div className="px-4 pb-3 text-sm" style={{ color: SLATE }}>
                          {f.answer}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {content.articles.length === 0 && content.faqs.length === 0 && (
              <p className="text-sm" style={{ color: SLATE }}>
                No help content has been published yet.
              </p>
            )}
          </div>
        )}

{view === "admin" && currentMember?.isAdmin && (
          <Suspense fallback={<div className="py-12 text-center text-sm" style={{ color: SLATE }}>Loading secure admin dashboard…</div>}>
            <SuperAdminDashboard scope={{
              ADMIN_ROLE_LABELS,
              ADMIN_ROLE_ORDER,
              Array,
              BACKEND_URL,
              BERRY,
              Boolean,
              CANVAS,
              CATEGORIES,
              CATEGORY_COLOR,
              CURRENCIES,
              Date,
              FULFILLMENT_LABEL,
              INK,
              ImageIcon,
              MARIGOLD,
              Math,
              Number,
              Object,
              Pencil,
              Plus,
              React,
              SAGE,
              SLATE,
              Set,
              StarDisplay,
              String,
              TICKET_STATUS_LABEL,
              Tag,
              Trash2,
              X,
              accountReports,
              activeAdminOrderId,
              activeDisputeCaseId,
              activeTicketId,
              addBanner,
              addFaq,
              adminApproveListing,
              adminApproveMember,
              adminAutoVerifySeller,
              adminDisputeSearch,
              adminDisputeStatusFilter,
              adminDisputes,
              adminLocalDeliveries,
              adminListingSearch,
              adminListingStatusFilter,
              adminMemberFilter,
              adminMemberSearch,
              adminOrderSearch,
              adminOrderStatusFilter,
              adminRejectListing,
              adminRemoveListing,
              adminRemoveMember,
              adminReportData,
              adminReportError,
              adminReportFrom,
              adminReportLoading,
              adminReportTo,
              adminReportType,
              adminResolveAccountReport,
              adminResolveMessageReport,
              adminResolveReviewReport,
              adminRestoreListing,
              adminSetRole,
              adminSetPreviewPhoneVerification,
              adminStaff,
              adminStaffError,
              adminStaffFilter,
              adminStaffSearch,
              adminTab,
              adminTakeDownListing,
              adminTempPasswordGeneratingId,
              adminTickets,
              adminToggleFeature,
              adminToggleImageVisibility,
              adminToggleSuspend,
              adminToggleVerify,
              adminRevokeLocalDelivery,
              adminTotpCodeInput,
              adminTotpError,
              adminTotpSetup,
              adminUpdateTicketStatus,
              auditActionFilter,
              auditDateFilter,
              auditLog,
              auditSearch,
              authFetch,
              authImageUploading,
              bannerForm,
              bannerImageUploading,
              buyerRiskData,
              buyerRiskError,
              buyerRiskFilter,
              buyerRiskLoading,
              buyerRiskSearch,
              casualSellerAdminLoading,
              casualSellerApplications,
              casualSellerReports,
              confirmAdminTotpSetup,
              confirmingAdminTotpSetup,
              content,
              contentTab,
              currentMember,
              currentUser,
              decidePremiumSellerApplication,
              dismissImageFlag,
              disputeAdminDrafts,
              downloadAdminReportCsv,
              downloadCasualSellerReport,
              downloadPremiumSellerReport,
              downloadVerifiedSellerReport,
              editingFaqId,
              expandedBuyerRiskId,
              expandedDocsUsername,
              expandedListingImagesId,
              expandedSellerPerformanceId,
              expandedStaffId,
              faqForm,
              fetchAdminReport,
              fetchAdminLocalDeliveries,
              fetchAdminStaff,
              fetchAuditLog,
              fetchBuyerRisk,
              fetchCasualSellerVerification,
              fetchReconciliation,
              fetchSellerPerformance,
              fetchSystemHealth,
              fetchVerifiedSellerApplications,
              formatMoney,
              generateAdminTemporaryPassword,
              handleAuthImageSelect,
              handleBannerImageSelect,
              handleHomepageAdImageSelect,
              handleHomepageAdMobileImageSelect,
              hasAdminPermission,
              hideImageReason,
              hidingImageDraft,
              homepageAdSaving,
              homepageAdUploading,
              homepageAds,
              listings,
              loadingAdminStaff,
              loadingAuditLog,
              loadingTicketMessages,
              localDeliveryFilter,
              localDeliveryLoading,
              localDeliverySearch,
              localDriverReports,
              members,
              messageReports,
              newTicketMessageInput,
              openAdminDisputes,
              openAdminNotes,
              openAdminWarnings,
              openCasualApplicationEvidence,
              openTicketThread,
              orderNumber,
              orders,
              partialRefundOrder,
              paystackCheckingOrderId,
              paystackChecks,
              persistSettings,
              premiumSellerApplications,
              premiumSellerReports,
              reconciliationData,
              reconciliationError,
              reconciliationFilter,
              reconciliationLoading,
              reconciliationSearch,
              refundAdminFilter,
              refundAdminSearch,
              refundOrder,
              releasePayout,
              removeArticle,
              removeAuthImage,
              removeBanner,
              removeFaq,
              revealCasualSellerReportPassword,
              revealPremiumSellerReportPassword,
              revealVerifiedSellerReportPassword,
              reviewReports,
              revokeAdminStaffSessions,
              runPremiumSellerReportNow,
              runVerifiedSellerReportNow,
              saveAdminDisputeCase,
              saveHomepageAd,
              savingDisputeCaseId,
              sellerPerformanceData,
              sellerPerformanceError,
              sellerPerformanceFilter,
              sellerPerformanceLoading,
              sellerPerformanceSearch,
              sellerReports,
              sendTicketMessage,
              sendingTicketMessage,
              setActiveAdminOrderId,
              setActiveDisputeCaseId,
              setActiveTicketId,
              setAddMemberOpen,
              setAdminDisputeSearch,
              setAdminDisputeStatusFilter,
              setAdminListingSearch,
              setAdminListingStatusFilter,
              setAdminMemberFilter,
              setAdminMemberSearch,
              setAdminOrderSearch,
              setAdminOrderStatusFilter,
              setAdminReportData,
              setAdminReportError,
              setAdminReportFrom,
              setAdminReportTo,
              setAdminReportType,
              setAdminStaffFilter,
              setAdminStaffSearch,
              setAdminTab,
              setAdminTotpCodeInput,
              setAdminTotpError,
              setAdminTotpSetup,
              setArticleForm,
              setArticleModalOpen,
              setAuditActionFilter,
              setAuditDateFilter,
              setAuditSearch,
              setBannerForm,
              setBuyerRiskFilter,
              setBuyerRiskSearch,
              setContentTab,
              setDisputeAdminDrafts,
              setEditingArticleId,
              setEditingFaqId,
              setExpandedBuyerRiskId,
              setExpandedDocsUsername,
              setExpandedListingImagesId,
              setExpandedSellerPerformanceId,
              setExpandedStaffId,
              setFaqForm,
              setHideImageReason,
              setHidingImageDraft,
              setHomepageAds,
              setLocalDeliveryFilter,
              setLocalDeliverySearch,
              setNewTicketMessageInput,
              setOrders,
              setReconciliationFilter,
              setReconciliationSearch,
              setRefundAdminFilter,
              setRefundAdminSearch,
              setRejectModalUsername,
              setRejectReasonDraft,
              setSellerPerformanceFilter,
              setSellerPerformanceSearch,
              setSettings,
              setTicketMessages,
              settings,
              showToast,
              startAdminTotpSetup,
              startEdit,
              startingAdminTotpSetup,
              systemHealth,
              systemHealthError,
              systemHealthLoading,
              ticketMessages,
              updateBanner,
              updateFaq,
              updateSellerReport,
              updateLocalDriverReport,
              verifiedSellerApplications,
              verifiedSellerReports,
              verifyPaystackReconciliation,
              view,
              viewPremiumSellerDocument,
              viewVerifiedSellerBankStatement,
              viewVerifiedSellerIdentification,
              window,
              withdrawals,
            }} />
          </Suspense>
        )}


      </main>

      {adminNotesTarget && (
        <div className="fixed inset-0 z-[90] flex items-center justify-center p-4" style={{ backgroundColor: "rgba(27,36,48,0.58)" }}>
          <div className="w-full max-w-xl rounded-2xl bg-white shadow-xl overflow-hidden">
            <div className="p-5 border-b flex items-start justify-between gap-3" style={{ borderColor: "#EFEBE0" }}>
              <div>
                <h3 className="text-lg" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Private admin notes</h3>
                <p className="text-xs mt-1" style={{ color: SLATE }}>{adminNotesTarget.label}</p>
                <p className="text-xs mt-1" style={{ color: BERRY }}>Visible only to authorized Stallyard admins. Users never see these notes.</p>
              </div>
              <button type="button" onClick={() => setAdminNotesTarget(null)} aria-label="Close internal notes"><X size={20} style={{ color: SLATE }} /></button>
            </div>
            <div className="p-5 max-h-[55vh] overflow-y-auto">
              {adminNotesLoading ? (
                <p className="text-sm" style={{ color: SLATE }}>Loading notes…</p>
              ) : adminNotesList.length === 0 ? (
                <p className="text-sm" style={{ color: SLATE }}>No internal notes yet.</p>
              ) : (
                <div className="space-y-2">
                  {adminNotesList.map((note) => (
                    <div key={note.id} className="p-3 rounded-lg border" style={{ borderColor: "#DDD8CC", backgroundColor: CANVAS }}>
                      <p className="text-sm whitespace-pre-wrap" style={{ color: INK }}>{note.body}</p>
                      <p className="text-xs mt-2" style={{ color: SLATE }}>
                        {note.admin_display_name || note.admin_username || "Admin"} · {new Date(note.created_at).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="p-5 border-t" style={{ borderColor: "#EFEBE0" }}>
              <textarea
                value={adminNoteDraft}
                onChange={(e) => setAdminNoteDraft(e.target.value)}
                maxLength={4000}
                rows={3}
                placeholder="Add a private note for other admins…"
                className="w-full px-3 py-2 rounded-lg border outline-none text-sm"
                style={{ borderColor: "#DDD8CC", color: INK }}
              />
              <div className="flex items-center justify-between gap-3 mt-2">
                <span className="text-xs" style={{ color: SLATE }}>{adminNoteDraft.length}/4000 · Notes are append-only for accountability.</span>
                <button type="button" onClick={addAdminNote} disabled={adminNoteSaving || !adminNoteDraft.trim()} className="px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50" style={{ backgroundColor: MARIGOLD, color: INK }}>
                  {adminNoteSaving ? "Saving…" : "Add note"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isAdminHost() ? (
        <footer style={{ backgroundColor: INK }} className="mt-12">
          <div className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between flex-wrap gap-3">
            <div>
              <p className="text-xs font-semibold" style={{ color: "#C9CCD3" }}>Stallyard Admin · Restricted staff system</p>
              <p className="text-[11px] mt-1" style={{ color: "#8A93A3" }}>Authorized staff access only. Administrative actions may be recorded in the audit log.</p>
            </div>
            {currentUser && (
              <button onClick={logout} className="text-xs font-medium underline" style={{ color: "#C9CCD3" }}>Sign out</button>
            )}
          </div>
        </footer>
      ) : (
        <footer style={{ backgroundColor: INK }} className="mt-16">
        <div className="max-w-6xl mx-auto px-6 py-12 grid grid-cols-2 sm:grid-cols-4 gap-8">
          <div>
            <h3 className="text-xs font-semibold mb-3 tracking-wide" style={{ color: "#8A93A3" }}>
              Shop
            </h3>
            <div className="flex flex-col gap-2">
              <button
                onClick={() => {
                  setCategoryFilter("All");
                  setSubcategoryFilter("All");
                  setSearch("");
                  setSelected(null);
                  setView("browse");
                  window.scrollTo({ top: 0, behavior: "smooth" });
                }}
                className="text-sm text-left"
                style={{ color: "#E5E7EB" }}
              >
                Browse listings
              </button>
              <button
                onClick={() => { setSelected(null); setView("categories"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                className="text-sm text-left"
                style={{ color: "#E5E7EB" }}
              >
                Categories
              </button>
              <button onClick={() => { setSelected(null); setView("how-it-works"); window.scrollTo({ top: 0, behavior: "smooth" }); }} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                How it works
              </button>
              <button
                onClick={() => { setSelected(null); setView("create-account"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                className="text-sm text-left"
                style={{ color: "#E5E7EB" }}
              >
                Create an account
              </button>
            </div>
          </div>

          <div>
            <h3 className="text-xs font-semibold mb-3 tracking-wide" style={{ color: "#8A93A3" }}>
              Sell
            </h3>
            <div className="flex flex-col gap-2">
              <button onClick={() => { setSelected(null); setView("become-seller"); window.scrollTo({ top: 0, behavior: "smooth" }); }} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Become a seller
              </button>
              <button
                onClick={() => { setSelected(null); setView("shipping-delivery"); window.scrollTo({ top: 0, behavior: "smooth" }); }}
                className="text-sm text-left"
                style={{ color: "#E5E7EB" }}
              >
                Shipping & delivery
              </button>
              <button onClick={() => setView("wallet")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Getting paid
              </button>
              <a href="/driver/dashboard" className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Drive for Stallyard
              </a>
            </div>
          </div>

          <div>
            <h3 className="text-xs font-semibold mb-3 tracking-wide" style={{ color: "#8A93A3" }}>
              Support
            </h3>
            <div className="flex flex-col gap-2">
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Contact support
              </button>
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Help center
              </button>
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Marketplace policies
              </button>
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Returns & disputes
              </button>
            </div>
          </div>

          <div>
            <h3 className="text-xs font-semibold mb-3 tracking-wide" style={{ color: "#8A93A3" }}>
              Stallyard
            </h3>
            <div className="flex flex-col gap-2">
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Seller rules
              </button>
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Prohibited items
              </button>
              <button onClick={() => setView("help")} className="text-sm text-left" style={{ color: "#E5E7EB" }}>
                Fees
              </button>
              <a
                href="https://legal.stallyard.com/user-agreement/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-left"
                style={{ color: "#E5E7EB" }}
              >
                User Agreement
              </a>
            </div>
          </div>
        </div>
        <div
          className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between flex-wrap gap-3"
          style={{ borderTop: "1px solid rgba(255,255,255,0.1)" }}
        >
          <p className="text-xs" style={{ color: "#8A93A3" }}>
            © {new Date().getFullYear()} Stallyard. Payments processed securely through Paystack.
          </p>
        </div>
        </footer>

      )}

      {/* Detail modal */}
      {selected && (() => {
        const liveSelected = listings.find((l) => l.id === selected.id) || selected;
        const isAuction = liveSelected.listingType === "auction";
        const timeLeft = isAuction ? formatTimeRemaining(liveSelected.auctionEndTime, nowTick) : null;
        const auctionEnded = isAuction && !timeLeft;
        const isHighBidder = liveSelected.highestBidderUsername === currentUser;
        return (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setSelected(null)}
        >
          <div
            className="bg-white rounded-2xl max-w-md w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setSelected(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            {selected.images && selected.images.length > 0 ? (
              <div className="mb-3">
                <div
                  className="relative"
                  tabIndex={0}
                  role="group"
                  aria-label={`Photo ${activeImg + 1} of ${selected.images.length}`}
                  onKeyDown={(e) => {
                    if (e.key === "ArrowLeft") setActiveImg((i) => (i > 0 ? i - 1 : selected.images.length - 1));
                    if (e.key === "ArrowRight") setActiveImg((i) => (i < selected.images.length - 1 ? i + 1 : 0));
                  }}
                  onTouchStart={(e) => {
                    touchState.current.startX = e.touches[0].clientX;
                  }}
                  onTouchEnd={(e) => {
                    const startX = touchState.current.startX;
                    if (startX == null || selected.images.length <= 1) return;
                    const deltaX = e.changedTouches[0].clientX - startX;
                    // A deliberate swipe, not just a tap — 40px is enough to
                    // feel responsive without triggering on an accidental
                    // finger drift while tapping the photo to zoom.
                    if (Math.abs(deltaX) > 40) {
                      if (deltaX < 0) setActiveImg((i) => (i < selected.images.length - 1 ? i + 1 : 0));
                      else setActiveImg((i) => (i > 0 ? i - 1 : selected.images.length - 1));
                    }
                    touchState.current.startX = null;
                  }}
                >
                  <img
                    src={selected.images[activeImg]}
                    srcSet={responsiveListingSrcSet(selected.images[activeImg])}
                    sizes="(max-width: 640px) calc(100vw - 32px), 448px"
                    alt={`${selected.title} — photo ${activeImg + 1} of ${selected.images.length}`}
                    className="w-full h-56 object-cover rounded-xl cursor-zoom-in"
                    onClick={() => setGalleryZoomOpen(true)}
                    onError={(e) => {
                      e.currentTarget.onerror = null;
                      e.currentTarget.src =
                        "data:image/svg+xml;utf8," +
                        encodeURIComponent(
                          `<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300'><rect width='100%' height='100%' fill='#F6F3EC'/><text x='50%' y='50%' text-anchor='middle' fill='#667085' font-family='sans-serif' font-size='16'>Photo unavailable</text></svg>`
                        );
                    }}
                  />
                  {selected.images.length > 1 && (
                    <>
                      <button
                        onClick={() => setActiveImg((i) => (i > 0 ? i - 1 : selected.images.length - 1))}
                        aria-label="Previous photo"
                        className="absolute left-2 top-1/2 -translate-y-1/2 w-8 h-8 rounded-full flex items-center justify-center"
                        style={{ backgroundColor: "rgba(27,36,48,0.6)", color: "white" }}
                      >
                        ‹
                      </button>
                      <button
                        onClick={() => setActiveImg((i) => (i < selected.images.length - 1 ? i + 1 : 0))}
                        aria-label="Next photo"
                        className="absolute right-2 top-1/2 -translate-y-1/2 w-8 h-8 rounded-full flex items-center justify-center"
                        style={{ backgroundColor: "rgba(27,36,48,0.6)", color: "white" }}
                      >
                        ›
                      </button>
                      <span
                        className="absolute bottom-2 right-2 text-xs px-2 py-0.5 rounded-full"
                        style={{ backgroundColor: "rgba(27,36,48,0.6)", color: "white" }}
                      >
                        {activeImg + 1} of {selected.images.length}
                      </span>
                    </>
                  )}
                </div>
                {selected.images.length > 1 && (
                  <div className="flex gap-2 mt-2">
                    {selected.images.map((src, idx) => (
                      <button
                        key={idx}
                        onClick={() => setActiveImg(idx)}
                        className="w-14 h-14 rounded-lg overflow-hidden border-2"
                        style={{ borderColor: idx === activeImg ? MARIGOLD : "transparent" }}
                        aria-label={`View photo ${idx + 1}`}
                        aria-current={idx === activeImg}
                      >
                        <img src={src} srcSet={responsiveListingSrcSet(src)} sizes="56px" alt="" loading="lazy" decoding="async" className="w-full h-full object-cover" />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="text-4xl mb-3">{selected.emoji}</div>
            )}
            <h3 className="text-xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              {selected.title}
            </h3>
            <div
              className="text-2xl mb-3"
              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
            >
              {formatMoney(Number(selected.price))}
            </div>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              {selected.description || "No description provided."}
            </p>
            {selected.category === "Auto Parts" && (selected.fitMake || selected.fitModel) && (
              <p
                className="text-sm font-medium mb-4 px-3 py-2 rounded-lg"
                style={{ color: CATEGORY_COLOR["Auto Parts"], backgroundColor: CANVAS }}
              >
                Fits: {[selected.fitMake, selected.fitModel, selected.fitYear].filter(Boolean).join(" ")}
              </p>
            )}
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5">
                <Tag color={CATEGORY_COLOR[selected.category] || SLATE}>{selected.category}</Tag>
                <Tag color={CONDITION_COLOR[selected.condition] || SAGE}>{selected.condition || "New"}</Tag>
              </div>
              <div className="flex items-center gap-2">
                {(() => {
                  const rep = getSellerReputation(selected.ownerUsername);
                  return rep ? (
                    <span
                      className="text-xs font-medium"
                      style={{ color: rep.positivePct >= 90 ? SAGE : rep.positivePct >= 70 ? MARIGOLD : BERRY }}
                    >
                      {rep.positivePct}% positive
                    </span>
                  ) : null;
                })()}
                <button
                  onClick={() => openStorefront(selected.ownerUsername)}
                  className="text-xs underline"
                  style={{ color: SLATE }}
                >
                  sold by {selected.sellerName}
                </button>
              </div>
            </div>
            {(() => {
              const vacation = getSellerVacationInfo(selected.ownerUsername);
              if (!vacation) return null;
              return (
                <div
                  className="mb-4 px-3 py-2 rounded-lg text-xs"
                  style={{ backgroundColor: "#FBF0DC", color: INK }}
                >
                  🌴 This seller is on vacation
                  {vacation.returnDate
                    ? ` until ${new Date(vacation.returnDate).toLocaleDateString(undefined, { month: "short", day: "numeric" })}`
                    : ""}
                  . {vacation.message || "Orders may ship later than usual."}
                </div>
              );
            })()}
            {(() => {
              const rating = getListingRating(selected.id);
              return rating ? (
                <div className="flex items-center gap-2 mb-2">
                  <StarDisplay value={rating.avg} />
                  <span className="text-xs" style={{ color: SLATE }}>
                    {rating.avg.toFixed(1)} ({rating.count} review{rating.count !== 1 ? "s" : ""})
                  </span>
                </div>
              ) : (
                <p className="text-xs mb-2" style={{ color: SLATE }}>
                  No reviews yet.
                </p>
              );
            })()}
            <p className="text-xs mb-5" style={{ color: SLATE }}>
              {selected.shippingFee
                ? `+ ${formatMoney(selected.shippingFee, selected.currency)} shipping`
                : "Free shipping"}
            </p>
            {isAuction ? (
              <div>
                <div
                  className="p-3 rounded-lg mb-4"
                  style={{ backgroundColor: "#E3EDF4" }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs" style={{ color: "#3B6E8F" }}>
                      Current bid
                    </span>
                    <span className="text-xs font-medium" style={{ color: "#3B6E8F" }}>
                      {auctionEnded ? "Auction ended" : timeLeft}
                    </span>
                  </div>
                  <div
                    className="text-2xl font-semibold"
                    style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                  >
                    {formatMoney(liveSelected.price, liveSelected.currency)}
                  </div>
                  <div className="text-xs mt-1" style={{ color: SLATE }}>
                    {(liveSelected.bidHistory || []).length} bid
                    {(liveSelected.bidHistory || []).length !== 1 ? "s" : ""}
                    {liveSelected.highestBidderUsername &&
                      ` · highest bidder: ${
                        liveSelected.highestBidderUsername === currentUser
                          ? "you"
                          : liveSelected.bidHistory[liveSelected.bidHistory.length - 1]?.bidderName || "someone"
                      }`}
                  </div>
                </div>

                {auctionEnded ? (
                  isHighBidder ? (
                    <button
                      onClick={() => {
                        addToCartAtPrice(liveSelected, liveSelected.price);
                        setSelected(null);
                      }}
                      className="w-full py-2.5 rounded-lg font-medium flex items-center justify-center gap-2 mb-3"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      <ShoppingBag size={16} />
                      You won! Add to cart at {formatMoney(liveSelected.price, liveSelected.currency)}
                    </button>
                  ) : (
                    <p className="text-sm text-center mb-3" style={{ color: SLATE }}>
                      {(liveSelected.bidHistory || []).length === 0
                        ? "This auction ended with no bids."
                        : "This auction has ended."}
                    </p>
                  )
                ) : (
                  <div className="flex items-center gap-2 mb-3">
                    <span style={{ color: SLATE }}>{CURRENCIES.NGN.symbol}</span>
                    <input
                      type="number"
                      min={Number(liveSelected.price) + 1}
                      step="0.01"
                      value={bidAmount}
                      onChange={(e) => setBidAmount(e.target.value)}
                      placeholder={(Number(liveSelected.price) + 1).toFixed(2)}
                      className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                      style={{ borderColor: "#DDD8CC" }}
                    />
                    <button
                      onClick={() => placeBid(liveSelected, bidAmount)}
                      className="px-4 py-2 rounded-lg font-medium"
                      style={{ backgroundColor: MARIGOLD, color: INK }}
                    >
                      Place bid
                    </button>
                  </div>
                )}

                <div className="flex gap-3">
                  <button
                    onClick={() => toggleWatchlist(liveSelected.id)}
                    className="flex-1 py-2.5 px-4 rounded-lg font-medium border flex items-center justify-center gap-2"
                    style={{
                      borderColor: watchlist.includes(liveSelected.id) ? BERRY : "#DDD8CC",
                      color: watchlist.includes(liveSelected.id) ? BERRY : SLATE,
                    }}
                  >
                    <Heart size={16} fill={watchlist.includes(liveSelected.id) ? BERRY : "none"} />
                    {watchlist.includes(liveSelected.id) ? "Saved" : "Watch"}
                  </button>
                  <button
                    onClick={() => startOrOpenThread(liveSelected)}
                    className="flex-1 py-2.5 rounded-lg font-medium border"
                    style={{ borderColor: "#DDD8CC", color: SLATE }}
                  >
                    Message seller
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex gap-3">
                <button
                  onClick={() => addToCart(selected)}
                  className="flex-1 py-2.5 rounded-lg font-medium flex items-center justify-center gap-2"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  <ShoppingBag size={16} />
                  Add to cart
                </button>
                <button
                  onClick={() => toggleWatchlist(selected.id)}
                  className="py-2.5 px-4 rounded-lg font-medium border flex items-center justify-center gap-2"
                  style={{
                    borderColor: watchlist.includes(selected.id) ? BERRY : "#DDD8CC",
                    color: watchlist.includes(selected.id) ? BERRY : SLATE,
                  }}
                  aria-label={watchlist.includes(selected.id) ? "Remove from watchlist" : "Save to watchlist"}
                >
                  <Heart size={16} fill={watchlist.includes(selected.id) ? BERRY : "none"} />
                </button>
                <button
                  onClick={() => startOrOpenThread(selected)}
                  className="flex-1 py-2.5 rounded-lg font-medium border"
                  style={{ borderColor: "#DDD8CC", color: SLATE }}
                >
                  Message seller
                </button>
              </div>
            )}
          </div>
        </div>
        );
      })()}

      {/* Full-screen zoomed gallery — opened by tapping the main photo above */}
      {galleryZoomOpen && selected?.images?.length > 0 && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center overflow-hidden"
          style={{ backgroundColor: "rgba(0,0,0,0.92)" }}
          onClick={() => zoomScale <= 1 && setGalleryZoomOpen(false)}
          role="dialog"
          aria-label="Zoomed photo viewer"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Escape") setGalleryZoomOpen(false);
            if (e.key === "ArrowLeft") setActiveImg((i) => (i > 0 ? i - 1 : selected.images.length - 1));
            if (e.key === "ArrowRight") setActiveImg((i) => (i < selected.images.length - 1 ? i + 1 : 0));
          }}
          onTouchStart={handleZoomTouchStart}
          onTouchMove={handleZoomTouchMove}
          onTouchEnd={handleZoomTouchEnd}
        >
          <button
            onClick={() => setGalleryZoomOpen(false)}
            aria-label="Close zoomed view"
            className="absolute top-4 right-4 w-10 h-10 rounded-full flex items-center justify-center"
            style={{ backgroundColor: "rgba(255,255,255,0.15)", color: "white" }}
          >
            <X size={20} />
          </button>
          <img
            src={selected.images[activeImg]}
            srcSet={responsiveListingSrcSet(selected.images[activeImg])}
            sizes="100vw"
            alt={`${selected.title} — zoomed photo ${activeImg + 1} of ${selected.images.length}`}
            className="max-w-full max-h-full object-contain"
            style={{
              transform: `scale(${zoomScale}) translate(${zoomOffset.x / zoomScale}px, ${zoomOffset.y / zoomScale}px)`,
              touchAction: "none",
            }}
            onClick={(e) => e.stopPropagation()}
          />
          {selected.images.length > 1 && (
            <>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setActiveImg((i) => (i > 0 ? i - 1 : selected.images.length - 1));
                }}
                aria-label="Previous photo"
                className="absolute left-4 top-1/2 -translate-y-1/2 w-10 h-10 rounded-full flex items-center justify-center"
                style={{ backgroundColor: "rgba(255,255,255,0.15)", color: "white" }}
              >
                ‹
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setActiveImg((i) => (i < selected.images.length - 1 ? i + 1 : 0));
                }}
                aria-label="Next photo"
                className="absolute right-4 top-1/2 -translate-y-1/2 w-10 h-10 rounded-full flex items-center justify-center"
                style={{ backgroundColor: "rgba(255,255,255,0.15)", color: "white" }}
              >
                ›
              </button>
              <span
                className="absolute bottom-4 left-1/2 -translate-x-1/2 text-sm px-3 py-1 rounded-full"
                style={{ backgroundColor: "rgba(255,255,255,0.15)", color: "white" }}
              >
                {activeImg + 1} of {selected.images.length}
              </span>
            </>
          )}
        </div>
      )}

      {/* Cart drawer */}
      {cartOpen && (
        <div
          className="fixed inset-0 z-40 flex justify-end"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setCartOpen(false)}
        >
          <div
            className="bg-white h-full w-full max-w-sm p-6 overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
                Your cart
              </h3>
              <button onClick={() => setCartOpen(false)} aria-label="Close cart">
                <X size={20} style={{ color: SLATE }} />
              </button>
            </div>

            {cartItems.length === 0 ? (
              <div className="text-center py-16">
                <ShoppingBag size={32} className="mx-auto mb-3" style={{ color: SLATE }} />
                <p className="text-sm" style={{ color: SLATE }}>
                  Your cart is empty.
                </p>
              </div>
            ) : (
              <>
                <div className="space-y-4 mb-6">
                  {cartItems.map((item) => (
                    <div key={item.id} className="flex gap-3">
                      <div className="text-2xl">{item.emoji}</div>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-sm truncate" style={{ color: INK }}>
                          {item.title}
                        </div>
                        <div
                          className="text-xs mt-0.5 flex items-center gap-2"
                          style={{ fontFamily: "'IBM Plex Mono', monospace", color: SLATE }}
                        >
                          {formatMoney(item.price, item.currency)} each
                          {item.isOfferPrice && <Tag color={MARIGOLD}>Offer price</Tag>}
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                          <button
                            onClick={() => updateCartQty(item.id, item.qty - 1)}
                            className="w-6 h-6 rounded-md border flex items-center justify-center"
                            style={{ borderColor: "#DDD8CC" }}
                            aria-label="Decrease quantity"
                          >
                            <Minus size={12} style={{ color: SLATE }} />
                          </button>
                          <span
                            className="text-sm w-5 text-center"
                            style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                          >
                            {item.qty}
                          </span>
                          <button
                            onClick={() => updateCartQty(item.id, item.qty + 1)}
                            className="w-6 h-6 rounded-md border flex items-center justify-center"
                            style={{ borderColor: "#DDD8CC" }}
                            aria-label="Increase quantity"
                          >
                            <Plus size={12} style={{ color: SLATE }} />
                          </button>
                        </div>
                      </div>
                      <div className="flex flex-col items-end justify-between">
                        <span
                          className="text-sm font-medium"
                          style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                        >
                          {formatMoney(item.price * item.qty, item.currency)}
                        </span>
                        <button onClick={() => removeFromCart(item.id)} aria-label="Remove item">
                          <Trash2 size={14} style={{ color: BERRY }} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="border-t pt-4 mb-4" style={{ borderColor: "#DDD8CC" }}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span style={{ color: SLATE }}>Subtotal</span>
                    <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                      {formatMoney(cartSubtotal, cartCurrency)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span style={{ color: SLATE }}>Shipping</span>
                    <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                      {cartShipping > 0 ? formatMoney(cartShipping, cartCurrency) : "Free"}
                    </span>
                  </div>
                  {cartTax > 0 && (
                    <div className="flex items-center justify-between text-sm mb-2">
                      <span style={{ color: SLATE }}>Tax ({Math.round((settings.taxRate || 0) * 1000) / 10}%)</span>
                      <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                        {formatMoney(cartTax, cartCurrency)}
                      </span>
                    </div>
                  )}
                  <div className="flex items-center justify-between pt-2 border-t" style={{ borderColor: "#EFEBE0" }}>
                    <span className="text-sm" style={{ color: SLATE }}>
                      Total
                    </span>
                    <span
                      className="text-xl"
                      style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
                    >
                      {formatMoney(cartTotal, cartCurrency)}
                    </span>
                  </div>
                </div>

                {currentUser && (
                  <div className="border-t pt-4 mb-4" style={{ borderColor: "#DDD8CC" }}>
                    <h4 className="text-sm font-semibold mb-2" style={{ color: INK }}>
                      Shipping address
                    </h4>
                    {savedAddresses.length > 0 && (
                      <div className="flex flex-wrap gap-2 mb-2">
                        {savedAddresses.map((a) => (
                          <button
                            key={a.id}
                            onClick={() =>
                              setShippingForm({
                                ...shippingForm,
                                fullName: a.full_name || shippingForm.fullName,
                                phone: a.phone || shippingForm.phone,
                                street: a.street,
                                city: a.city,
                                state: a.state,
                                zip: a.zip,
                                country: "Nigeria",
                                deliveryInstructions: a.delivery_instructions || "",
                                preferredDeliveryTime: a.preferred_delivery_time || "",
                                locationPhotos: a.location_photos || [],
                              })
                            }
                            className="text-xs px-2 py-1 rounded-full border"
                            style={{ borderColor: "#DDD8CC", color: INK }}
                          >
                            {a.label || `${a.city}, ${a.country}`}
                          </button>
                        ))}
                      </div>
                    )}
                    <div className="space-y-2">
                      <input
                        value={shippingForm.fullName}
                        onChange={(e) => setShippingForm({ ...shippingForm, fullName: e.target.value })}
                        placeholder="Full name"
                        className="w-full px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <input
                        value={shippingForm.phone}
                        onChange={(e) => setShippingForm({ ...shippingForm, phone: e.target.value })}
                        placeholder="Recipient phone number"
                        className="w-full px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <input
                        value={shippingForm.street}
                        onChange={(e) => setShippingForm({ ...shippingForm, street: e.target.value })}
                        placeholder="Street address"
                        className="w-full px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <div className="flex gap-2">
                        <input
                          value={shippingForm.city}
                          onChange={(e) => setShippingForm({ ...shippingForm, city: e.target.value })}
                          placeholder="City"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <input
                          value={shippingForm.state}
                          onChange={(e) => setShippingForm({ ...shippingForm, state: e.target.value })}
                          placeholder="State"
                          className="w-28 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                      </div>
                      <textarea
                        value={shippingForm.deliveryInstructions}
                        onChange={(e) => setShippingForm({ ...shippingForm, deliveryInstructions: e.target.value.slice(0, 1000) })}
                        placeholder="Private delivery instructions or nearby landmark (optional)"
                        rows={3}
                        className="w-full px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <input
                        value={shippingForm.preferredDeliveryTime}
                        onChange={(e) => setShippingForm({ ...shippingForm, preferredDeliveryTime: e.target.value.slice(0, 200) })}
                        placeholder="Preferred delivery time (optional)"
                        className="w-full px-3 py-2 rounded-lg border outline-none text-sm"
                        style={{ borderColor: "#DDD8CC" }}
                      />
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <span className="text-xs font-medium" style={{ color: INK }}>Private location photos (up to 5)</span>
                          <label className="text-xs font-medium underline cursor-pointer" style={{ color: SLATE }}>
                            {uploadingLocationPhotos ? "Processing…" : "Add photos"}
                            <input type="file" accept="image/*" multiple className="hidden" onChange={handleDeliveryLocationPhotos} disabled={uploadingLocationPhotos || (shippingForm.locationPhotos || []).length >= 5} />
                          </label>
                        </div>
                        <div className="flex gap-2 flex-wrap">
                          {(shippingForm.locationPhotos || []).map((photo, index) => (
                            <div key={index} className="relative">
                              <img src={photo} alt={`Delivery location ${index + 1}`} className="w-16 h-16 object-cover rounded-lg border" style={{ borderColor: "#DDD8CC" }} />
                              <button type="button" onClick={() => setShippingForm((form) => ({ ...form, locationPhotos: form.locationPhotos.filter((_, i) => i !== index) }))} className="absolute -top-1 -right-1 bg-white border rounded-full" aria-label="Remove location photo"><X size={13} /></button>
                            </div>
                          ))}
                        </div>
                        <p className="text-xs mt-1" style={{ color: SLATE }}>Visible only to the seller handling this paid order and authorized support staff.</p>
                      </div>
                      <div className="flex gap-2">
                        <input
                          value={shippingForm.zip}
                          onChange={(e) => setShippingForm({ ...shippingForm, zip: e.target.value })}
                          placeholder="Postal code"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm"
                          style={{ borderColor: "#DDD8CC" }}
                        />
                        <input
                          value="Nigeria"
                          readOnly
                          aria-label="Country"
                          className="flex-1 px-3 py-2 rounded-lg border outline-none text-sm bg-gray-50"
                          style={{ borderColor: "#DDD8CC", color: INK }}
                        />
                      </div>
                      <label className="flex items-center gap-2 text-xs pt-1" style={{ color: SLATE }}>
                        <input
                          type="checkbox"
                          checked={saveShippingAddress}
                          onChange={(e) => setSaveShippingAddress(e.target.checked)}
                        />
                        Save this address to my account for next time
                      </label>
                      {shippingError && (
                        <p className="text-xs" style={{ color: BERRY }}>
                          {shippingError}
                        </p>
                      )}
                      <p className="text-xs" style={{ color: SLATE }}>Your delivery details are shared only with the seller handling the paid order and authorized support staff.</p>
                    </div>
                  </div>
                )}

                {savedCards.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-medium mb-2" style={{ color: SLATE }}>
                      Pay with a saved card
                    </p>
                    <div className="space-y-2">
                      {savedCards.map((c) => (
                        <button
                          key={c.id}
                          onClick={() => payWithSavedCard(c.id)}
                          disabled={checkoutSubmitting}
                          className="w-full text-left px-3 py-2 rounded-lg border bg-white text-sm disabled:opacity-50"
                          style={{ borderColor: "#DDD8CC", color: INK }}
                        >
                          {c.card_type ? c.card_type.charAt(0).toUpperCase() + c.card_type.slice(1) : "Card"}
                          {c.last4 ? ` ending in ${c.last4}` : ""}
                          {c.is_default ? " (default)" : ""}
                        </button>
                      ))}
                    </div>
                    <p className="text-xs text-center mt-2" style={{ color: SLATE }}>
                      Or pay with a new card below
                    </p>
                  </div>
                )}

                <button
                  onClick={checkout}
                  disabled={checkoutSubmitting}
                  className="w-full py-2.5 rounded-lg font-medium disabled:opacity-50"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {checkoutSubmitting ? "Starting checkout…" : "Checkout"}
                </button>
                <label className="flex items-center gap-2 text-xs mt-2 justify-center" style={{ color: SLATE }}>
                  <input
                    type="checkbox"
                    checked={saveCardAtCheckout}
                    onChange={(e) => setSaveCardAtCheckout(e.target.checked)}
                  />
                  Save this card for future purchases
                </label>
                <p className="text-xs text-center mt-2" style={{ color: SLATE }}>
                  You'll be taken to Paystack to pay securely.
                </p>
              </>
            )}
          </div>
        </div>
      )}

      {/* Shown right after Paystack redirects back, while /checkout/verify
          confirms the payment actually succeeded. */}
      {checkoutVerifying && (
        <div className="fixed inset-0 z-40 flex items-center justify-center p-4" style={{ backgroundColor: "rgba(27,36,48,0.5)" }}>
          <div className="bg-white rounded-2xl p-6 max-w-sm text-center">
            <p className="text-sm" style={{ color: INK }}>
              Confirming your payment…
            </p>
          </div>
        </div>
      )}

      {checkoutVerifyError && (
        <div className="fixed inset-0 z-40 flex items-center justify-center p-4" style={{ backgroundColor: "rgba(27,36,48,0.5)" }}>
          <div className="bg-white rounded-2xl p-6 max-w-sm text-center">
            <h2 className="text-xl mb-2" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Couldn't confirm payment
            </h2>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              {checkoutVerifyError}
            </p>
            <button
              onClick={() => setCheckoutVerifyError("")}
              className="px-4 py-2 rounded-lg text-sm font-medium"
              style={{ backgroundColor: MARIGOLD, color: INK }}
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Order confirmation modal */}
      {confirmedOrder && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setConfirmedOrder(null)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative text-center"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setConfirmedOrder(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <div
              className="w-12 h-12 rounded-full mx-auto mb-4 flex items-center justify-center text-2xl"
              style={{ backgroundColor: "#E7EFE8" }}
            >
              ✓
            </div>
            <h3 className="text-xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>
              Order confirmed
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              Thanks! Your order has been placed.
            </p>
            <div className="p-3 rounded-lg mb-4" style={{ backgroundColor: CANVAS }}>
              <div className="text-xs uppercase tracking-wide mb-1" style={{ color: SLATE }}>
                Confirmation number
              </div>
              <div
                className="text-lg font-semibold"
                style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
              >
                {orderNumber(confirmedOrder.id)}
              </div>
            </div>
            <div className="text-sm mb-4" style={{ color: SLATE }}>
              Total charged:{" "}
              <span style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}>
                {formatMoney(confirmedOrder.total, confirmedOrder.currency)}
              </span>
            </div>
            <button
              onClick={() => {
                setConfirmedOrder(null);
                setView("orders");
              }}
              className="w-full py-2.5 rounded-lg font-medium"
              style={{ backgroundColor: MARIGOLD, color: INK }}
            >
              View my orders
            </button>
          </div>
        </div>
      )}

      {/* Vacation mode settings modal */}
      {vacationOpen && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setVacationOpen(false)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setVacationOpen(false)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              🌴 Turn on vacation mode
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              Buyers will see a notice on your listings and when they add your items to their cart.
            </p>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Back on{" "}
                  <span className="font-normal" style={{ color: SLATE }}>
                    (optional)
                  </span>
                </label>
                <input
                  type="date"
                  value={vacationForm.returnDate}
                  onChange={(e) => setVacationForm({ ...vacationForm, returnDate: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Message to buyers{" "}
                  <span className="font-normal" style={{ color: SLATE }}>
                    (optional)
                  </span>
                </label>
                <textarea
                  value={vacationForm.message}
                  onChange={(e) => setVacationForm({ ...vacationForm, message: e.target.value })}
                  rows={2}
                  placeholder="e.g. Orders will ship as soon as I'm back!"
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <button
                type="button"
                onClick={saveVacationSettings}
                className="w-full py-2.5 rounded-lg font-medium mt-1"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                Turn on vacation mode
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Retroactive ID verification modal (US sellers past the sales threshold) */}
      {idVerifyOpen && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setIdVerifyOpen(false)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setIdVerifyOpen(false)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Add ID verification
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              Stallyard requires approved seller verification to keep selling.
            </p>
            <div className="space-y-3">
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    ID type
                  </label>
                  <select
                    value={idVerifyForm.idType}
                    onChange={(e) => setIdVerifyForm({ ...idVerifyForm, idType: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none bg-white"
                    style={{ borderColor: "#DDD8CC" }}
                  >
                    <option>Passport</option>
                    <option>National ID</option>
                    <option>Driver's License</option>
                    <option>Residence/Work Permit (CERPAC)</option>
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Issuing country
                  </label>
                  <input
                    value={idVerifyForm.idCountry}
                    onChange={(e) => setIdVerifyForm({ ...idVerifyForm, idCountry: e.target.value })}
                    placeholder="Nigeria"
                    className="w-full px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC" }}
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  License number{" "}
                  <span className="font-normal" style={{ color: SLATE }}>
                    (self-reported, not verified)
                  </span>
                </label>
                <input
                  value={idVerifyForm.licenseNumber}
                  onChange={(e) => setIdVerifyForm({ ...idVerifyForm, licenseNumber: e.target.value })}
                  placeholder="Optional"
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <button
                type="button"
                onClick={submitIdVerification}
                className="w-full py-2.5 rounded-lg font-medium mt-1"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                Save & continue selling
              </button>
            </div>
          </div>
        </div>
      )}

      {rejectModalUsername && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setRejectModalUsername(null)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setRejectModalUsername(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Reject seller application
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              Let {rejectModalUsername} know why, so they can fix it and re-apply.
            </p>
            <textarea
              value={rejectReasonDraft}
              onChange={(e) => setRejectReasonDraft(e.target.value)}
              placeholder="e.g. Bank statement doesn't match the name on file"
              rows={3}
              className="w-full px-3 py-2 rounded-lg border outline-none mb-3"
              style={{ borderColor: "#DDD8CC" }}
            />
            <button
              type="button"
              onClick={() => {
                adminRejectMember(rejectModalUsername, rejectReasonDraft.trim());
                setRejectModalUsername(null);
              }}
              className="w-full py-2.5 rounded-lg font-medium"
              style={{ backgroundColor: BERRY, color: "white" }}
            >
              Reject application
            </button>
          </div>
        </div>
      )}

      {previewOpen && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setPreviewOpen(false)}
        >
          <div
            className="bg-white rounded-2xl max-w-md w-full p-6 relative max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setPreviewOpen(false)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-3" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Preview listing
            </h3>
            {form.images.length > 0 ? (
              <div className="flex gap-2 mb-3 overflow-x-auto">
                {form.images.map((src, idx) => (
                  <img
                    key={idx}
                    src={src}
                    alt={`Photo ${idx + 1}`}
                    className="w-20 h-20 object-cover rounded-lg shrink-0"
                  />
                ))}
              </div>
            ) : (
              <div className="text-4xl mb-3">{form.emoji}</div>
            )}
            <div className="font-medium text-lg mb-1" style={{ color: INK }}>
              {form.title || "Untitled listing"}
            </div>
            <div
              className="text-xl font-semibold mb-2"
              style={{ fontFamily: "'IBM Plex Mono', monospace", color: INK }}
            >
              {CURRENCIES.NGN.symbol}
              {form.price ? Number(form.price).toFixed(2) : "0.00"}
            </div>
            <div className="text-sm mb-3" style={{ color: SLATE }}>
              {form.category}{form.subcategory ? ` › ${form.subcategory}` : ""} · {form.condition}
              {form.quantity && ` · Qty: ${form.quantity}`}
            </div>
            {form.description && (
              <p className="text-sm mb-3" style={{ color: INK }}>
                {form.description}
              </p>
            )}
            <div className="text-xs space-y-1 mb-4" style={{ color: SLATE }}>
              {form.brand && <div>Brand: {form.brand}</div>}
              {form.sku && <div>SKU/part number: {form.sku}</div>}
              {form.category === "Auto Parts" && (form.fitMake || form.fitModel || form.fitYear) && (
                <div>
                  Fits: {form.fitMake} {form.fitModel} {form.fitYear}
                </div>
              )}
              {form.category === "Auto Parts" && form.vin && <div>VIN: {form.vin}</div>}
              {form.state && <div>Location: {form.state}</div>}
              {form.shippingMethods.length > 0 && (
                <div>
                  Shipping:{" "}
                  {form.shippingMethods
                    .map((v) => SHIPPING_METHODS.find((m) => m.value === v)?.label || v)
                    .join(", ")}
                </div>
              )}
              {form.returnPolicy && <div>Return policy: {form.returnPolicy}</div>}
            </div>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setPreviewOpen(false)}
                className="flex-1 py-2.5 rounded-lg font-medium border"
                style={{ borderColor: "#DDD8CC", color: SLATE }}
              >
                Back to edit
              </button>
              <button
                type="button"
                onClick={() => handleSubmit("publish")}
                className="flex-1 py-2.5 rounded-lg font-medium"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                Publish listing
              </button>
            </div>
          </div>
        </div>
      )}

      {packingSlipOrder && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setPackingSlipOrder(null)}
        >
          <style>{`
            @media print {
              body * { visibility: hidden; }
              #packing-slip-content, #packing-slip-content * { visibility: visible; }
              #packing-slip-content {
                position: absolute; top: 0; left: 0; width: 100%; padding: 24px;
              }
              #packing-slip-no-print { display: none !important; }
            }
          `}</style>
          <div
            className="bg-white rounded-2xl max-w-md w-full p-6 relative max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              id="packing-slip-no-print"
              onClick={() => setPackingSlipOrder(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <div id="packing-slip-content">
              <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
                Packing slip
              </h3>
              <p className="text-xs mb-4" style={{ color: SLATE }}>
                {orderNumber(packingSlipOrder.id)} · {new Date(packingSlipOrder.createdAt).toLocaleString()}
              </p>
              <div className="mb-4">
                <div className="text-xs font-medium uppercase tracking-wide mb-1" style={{ color: SLATE }}>
                  Ship to
                </div>
                {packingSlipOrder.shippingAddress ? (
                  <p className="text-sm" style={{ color: INK }}>
                    {packingSlipOrder.shippingAddress.fullName}
                    <br />
                    {packingSlipOrder.shippingAddress.street}
                    <br />
                    {packingSlipOrder.shippingAddress.city}
                    {packingSlipOrder.shippingAddress.state ? `, ${packingSlipOrder.shippingAddress.state}` : ""}{" "}
                    {packingSlipOrder.shippingAddress.zip}
                    <br />
                    {packingSlipOrder.shippingAddress.country}
                  </p>
                ) : (
                  <p className="text-sm" style={{ color: SLATE }}>
                    No shipping address on file.
                  </p>
                )}
              </div>
              <div className="mb-4">
                <div className="text-xs font-medium uppercase tracking-wide mb-2" style={{ color: SLATE }}>
                  Items
                </div>
                <div className="space-y-2">
                  {packingSlipOrder.items
                    .filter((i) => i.ownerUsername === currentUser)
                    .map((i) => (
                      <div key={i.id} className="flex items-center justify-between text-sm" style={{ color: INK }}>
                        <span>
                          {i.title} × {i.qty}
                        </span>
                        <span style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
                          {formatMoney((i.price * i.qty))}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
              <div className="pt-3 text-xs" style={{ borderTop: "1px solid #EFEBE0", color: SLATE }}>
                Sold by {currentMember?.displayName} on Stallyard
              </div>
            </div>
            <button
              id="packing-slip-no-print"
              onClick={() => window.print()}
              className="w-full py-2.5 rounded-lg font-medium mt-4"
              style={{ backgroundColor: MARIGOLD, color: INK }}
            >
              Print
            </button>
          </div>
        </div>
      )}

      {reportMessageId && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setReportMessageId(null)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setReportMessageId(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Report this message
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              An admin will review it. This doesn't notify the other person.
            </p>
            <textarea
              value={reportReasonDraft}
              onChange={(e) => setReportReasonDraft(e.target.value)}
              placeholder="What's wrong with this message? (optional)"
              rows={3}
              className="w-full px-3 py-2 rounded-lg border outline-none mb-3"
              style={{ borderColor: "#DDD8CC" }}
            />
            <button
              type="button"
              onClick={() => {
                reportMessage(reportMessageId, reportReasonDraft.trim());
                setReportMessageId(null);
              }}
              className="w-full py-2.5 rounded-lg font-medium"
              style={{ backgroundColor: BERRY, color: "white" }}
            >
              Submit report
            </button>
          </div>
        </div>
      )}

      {reportReviewId && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setReportReviewId(null)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setReportReviewId(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Report this review
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              An admin will review it for being abusive or fraudulent.
            </p>
            <textarea
              value={reviewReportReasonDraft}
              onChange={(e) => setReviewReportReasonDraft(e.target.value)}
              placeholder="What's wrong with this review? (optional)"
              rows={3}
              className="w-full px-3 py-2 rounded-lg border outline-none mb-3"
              style={{ borderColor: "#DDD8CC" }}
            />
            <button
              type="button"
              onClick={() => {
                reportReview(reportReviewId, reviewReportReasonDraft.trim());
                setReportReviewId(null);
              }}
              className="w-full py-2.5 rounded-lg font-medium"
              style={{ backgroundColor: BERRY, color: "white" }}
            >
              Submit report
            </button>
          </div>
        </div>
      )}

      {adminWarningsTarget && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setAdminWarningsTarget(null)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative max-h-[85vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setAdminWarningsTarget(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Warnings — {adminWarningsTarget.displayName}
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              Visible to both you and this seller. A lighter step than suspending.
            </p>
            {adminWarningsList.length === 0 ? (
              <p className="text-sm mb-4" style={{ color: SLATE }}>
                No warnings yet.
              </p>
            ) : (
              <div className="space-y-2 mb-4">
                {adminWarningsList.map((w) => (
                  <div key={w.id} className="text-sm p-3 rounded-lg" style={{ backgroundColor: CANVAS, color: INK }}>
                    {w.message}
                    <div className="text-xs mt-1" style={{ color: SLATE }}>
                      {new Date(w.created_at).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <textarea
              value={newWarningMessage}
              onChange={(e) => setNewWarningMessage(e.target.value)}
              placeholder="What's the warning about?"
              rows={3}
              className="w-full px-3 py-2 rounded-lg border outline-none mb-3"
              style={{ borderColor: "#DDD8CC" }}
            />
            <button
              type="button"
              onClick={issueWarning}
              disabled={issuingWarning}
              className="w-full py-2.5 rounded-lg font-medium disabled:opacity-50"
              style={{ backgroundColor: BERRY, color: "white" }}
            >
              {issuingWarning ? "Issuing..." : "Issue warning"}
            </button>
          </div>
        </div>
      )}

      {adminReauthStep && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
        >
          <div className="bg-white rounded-2xl max-w-sm w-full p-6 relative">
            <button
              onClick={() => setAdminReauthStep(null)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-1" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Confirm it's you
            </h3>
            <p className="text-sm mb-4" style={{ color: SLATE }}>
              The admin panel needs a fresh check, even though you're already signed in.
            </p>
            {adminReauthStep === "password" ? (
              <>
                <input
                  type="password"
                  value={adminReauthPassword}
                  onChange={(e) => setAdminReauthPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && submitAdminReauthPassword()}
                  placeholder="Your password"
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                  autoFocus
                />
                {adminReauthError && (
                  <p className="text-sm mb-2" style={{ color: BERRY }}>
                    {adminReauthError}
                  </p>
                )}
                <button
                  onClick={submitAdminReauthPassword}
                  disabled={adminReauthSubmitting}
                  className="w-full py-2.5 rounded-lg font-medium mt-1 disabled:opacity-50"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {adminReauthSubmitting ? "Checking..." : "Continue"}
                </button>
              </>
            ) : (
              <>
                <p className="text-sm mb-3" style={{ color: SLATE }}>
                  {adminReauthStep === "code-email"
                    ? "Step 3 of 3: enter the 6-digit code we just emailed you."
                    : "Step 2 of 3: enter the 6-digit code from your authenticator app. An email code comes next."}
                </p>
                <input
                  value={adminReauthCode}
                  onChange={(e) => setAdminReauthCode(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && submitAdminReauthCode()}
                  placeholder="6-digit code"
                  maxLength={6}
                  className="w-full mb-2 px-3 py-2 rounded-lg border outline-none text-center text-lg tracking-widest"
                  style={{ borderColor: "#DDD8CC", fontFamily: "'IBM Plex Mono', monospace" }}
                  autoFocus
                />
                {adminReauthError && (
                  <p className="text-sm mb-2" style={{ color: BERRY }}>
                    {adminReauthError}
                  </p>
                )}
                <button
                  onClick={submitAdminReauthCode}
                  disabled={adminReauthSubmitting}
                  className="w-full py-2.5 rounded-lg font-medium mt-1 disabled:opacity-50"
                  style={{ backgroundColor: MARIGOLD, color: INK }}
                >
                  {adminReauthSubmitting ? "Verifying..." : adminReauthStep === "code-email" ? "Unlock admin panel" : "Continue"}
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {sellerReportReceipt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: "rgba(27,36,48,0.65)" }} onClick={() => setSellerReportReceipt(null)}>
          <div className="bg-white rounded-2xl max-w-sm w-full p-6 text-center" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-xl" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Report received</h3>
            <p className="text-sm mt-2" style={{ color: SLATE }}>Save this reference if you contact Stallyard support.</p>
            <div className="p-3 rounded-lg mt-3 font-semibold" style={{ backgroundColor: CANVAS, color: INK, fontFamily: "'IBM Plex Mono', monospace" }}>{sellerReportReceipt}</div>
            <button onClick={() => setSellerReportReceipt(null)} className="w-full py-2 rounded-lg mt-4 font-medium" style={{ backgroundColor: INK, color: "white" }}>Done</button>
          </div>
        </div>
      )}

      {sellerReportTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: "rgba(27,36,48,0.65)" }} onClick={() => setSellerReportTarget(null)}>
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 relative max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => setSellerReportTarget(null)} className="absolute top-4 right-4" aria-label="Close"><X size={20} style={{ color: SLATE }} /></button>
            <h3 className="text-xl mb-1" style={{ fontFamily: "'DM Serif Display', serif", color: INK }}>Report {sellerReportTarget.sellerName}</h3>
            <p className="text-xs mb-4" style={{ color: SLATE }}>This sends a safety report to Stallyard. It does not request a refund or open a payment dispute.</p>
            {sellerReportTarget.orderId && <div className="text-xs mb-3" style={{ color: SLATE }}>Related order: {orderNumber(sellerReportTarget.orderId)}</div>}
            <label className="block text-sm font-medium mb-1" style={{ color: INK }}>Reason</label>
            <select value={sellerReportForm.reason} onChange={(e) => setSellerReportForm((form) => ({ ...form, reason: e.target.value }))} className="w-full px-3 py-2 rounded-lg border bg-white mb-3" style={{ borderColor: "#DDD8CC" }}>
              <option value="">Choose a reason</option>
              <option value="fraud">Fraud or scam</option><option value="counterfeit">Counterfeit item</option>
              <option value="harassment">Harassment</option><option value="prohibited_item">Prohibited item</option>
              <option value="misleading_listing">Misleading listing</option><option value="delivery_misconduct">Delivery misconduct</option><option value="other">Other</option>
            </select>
            <label className="block text-sm font-medium mb-1" style={{ color: INK }}>What happened?</label>
            <textarea value={sellerReportForm.details} onChange={(e) => setSellerReportForm((form) => ({ ...form, details: e.target.value }))} rows={5} maxLength={2000} placeholder="Give enough detail for Stallyard to investigate." className="w-full px-3 py-2 rounded-lg border mb-3" style={{ borderColor: "#DDD8CC" }} />
            <label className="inline-block px-3 py-2 rounded-lg border text-sm font-medium cursor-pointer" style={{ borderColor: "#DDD8CC", color: INK }}>
              Add evidence ({sellerReportForm.evidenceUrls.length}/5)
              <input type="file" accept="image/*" multiple onChange={addSellerReportEvidence} className="hidden" disabled={sellerReportForm.evidenceUrls.length >= 5} />
            </label>
            {sellerReportForm.evidenceUrls.length > 0 && <div className="flex gap-2 mt-3 flex-wrap">{sellerReportForm.evidenceUrls.map((url, index) => <div key={index} className="relative"><img src={url} alt={`Evidence ${index + 1}`} className="w-20 h-20 object-cover rounded-lg border" /><button onClick={() => setSellerReportForm((form) => ({ ...form, evidenceUrls: form.evidenceUrls.filter((_, i) => i !== index) }))} className="absolute -top-2 -right-2 w-5 h-5 rounded-full text-xs" style={{ backgroundColor: BERRY, color: "white" }}>×</button></div>)}</div>}
            <button onClick={submitSellerReport} disabled={submittingSellerReport} className="w-full py-2.5 rounded-lg font-medium mt-4 disabled:opacity-50" style={{ backgroundColor: BERRY, color: "white" }}>{submittingSellerReport ? "Submitting…" : "Submit seller report"}</button>
            <p className="text-xs mt-3" style={{ color: SLATE }}>The seller will not be shown your identity or report details through this feature.</p>
          </div>
        </div>
      )}

      {/* Admin: add member modal */}
      {addMemberOpen && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setAddMemberOpen(false)}
        >
          <div
            className="bg-white rounded-2xl max-w-sm w-full p-6 relative max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setAddMemberOpen(false)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-4" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              Add a new member
            </h3>
            <div className="space-y-3">
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    First name
                  </label>
                  <input
                    value={addMemberForm.firstName}
                    onChange={(e) => setAddMemberForm({ ...addMemberForm, firstName: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC" }}
                  />
                </div>
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                    Last name
                  </label>
                  <input
                    value={addMemberForm.lastName}
                    onChange={(e) => setAddMemberForm({ ...addMemberForm, lastName: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg border outline-none"
                    style={{ borderColor: "#DDD8CC" }}
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Stall name
                </label>
                <input
                  value={addMemberForm.displayName}
                  onChange={(e) => setAddMemberForm({ ...addMemberForm, displayName: e.target.value })}
                  placeholder="e.g. Maple & Co."
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Office location
                </label>
                <input
                  value={addMemberForm.officeLocation}
                  onChange={(e) => setAddMemberForm({ ...addMemberForm, officeLocation: e.target.value })}
                  placeholder="e.g. Downtown branch"
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Email
                </label>
                <input
                  value={addMemberForm.email}
                  onChange={(e) => setAddMemberForm({ ...addMemberForm, email: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                  autoCapitalize="none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Phone
                </label>
                <input
                  value={addMemberForm.phone}
                  onChange={(e) => setAddMemberForm({ ...addMemberForm, phone: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Username
                </label>
                <input
                  value={addMemberForm.username}
                  onChange={(e) => setAddMemberForm({ ...addMemberForm, username: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                  autoCapitalize="none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Password
                </label>
                <input
                  type="password"
                  value={addMemberForm.password}
                  onChange={(e) => setAddMemberForm({ ...addMemberForm, password: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <button
                type="button"
                onClick={async () => {
                  const ok = await adminAddMember(addMemberForm);
                  if (ok) {
                    setAddMemberOpen(false);
                    setAddMemberForm({
                      firstName: "",
                      lastName: "",
                      displayName: "",
                      officeLocation: "",
                      username: "",
                      email: "",
                      phone: "",
                      password: "",
                    });
                  }
                }}
                className="w-full py-2.5 rounded-lg font-medium mt-1"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                Add member
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Admin: add/edit help article modal */}
      {articleModalOpen && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(27,36,48,0.6)" }}
          onClick={() => setArticleModalOpen(false)}
        >
          <div
            className="bg-white rounded-2xl max-w-lg w-full p-6 relative max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => setArticleModalOpen(false)}
              className="absolute top-4 right-4"
              aria-label="Close"
            >
              <X size={20} style={{ color: SLATE }} />
            </button>
            <h3 className="text-lg font-semibold mb-4" style={{ color: INK, fontFamily: "'DM Serif Display', serif" }}>
              {editingArticleId ? "Edit article" : "New help article"}
            </h3>
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Title
                </label>
                <input
                  value={articleForm.title}
                  onChange={(e) => setArticleForm({ ...articleForm, title: e.target.value })}
                  placeholder="e.g. How do refunds work?"
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1" style={{ color: INK }}>
                  Body
                </label>
                <textarea
                  value={articleForm.body}
                  onChange={(e) => setArticleForm({ ...articleForm, body: e.target.value })}
                  rows={8}
                  className="w-full px-3 py-2 rounded-lg border outline-none"
                  style={{ borderColor: "#DDD8CC" }}
                />
              </div>
              <button
                type="button"
                onClick={async () => {
                  if (editingArticleId) {
                    await updateArticle(editingArticleId, articleForm);
                  } else {
                    await addArticle(articleForm);
                  }
                  setArticleModalOpen(false);
                  setArticleForm({ title: "", body: "" });
                  setEditingArticleId(null);
                }}
                className="w-full py-2.5 rounded-lg font-medium mt-1"
                style={{ backgroundColor: MARIGOLD, color: INK }}
              >
                {editingArticleId ? "Save changes" : "Publish article"}
              </button>
            </div>
          </div>
        </div>
      )}
      {deliveryPhotoTarget && <LiveDeliveryPhotoCamera onSave={saveLiveDeliveryPhoto} onClose={() => setDeliveryPhotoTarget(null)} busy={uploadingPodKey !== null} />}
      {deliverySelfieCameraTarget && (
        <div
          className="fixed inset-0 z-[110] flex items-center justify-center p-4"
          style={{ backgroundColor: "rgba(10,15,22,.86)" }}
        >
          <div className="w-full max-w-md rounded-2xl bg-white p-4 shadow-xl">
            <div className="flex items-start justify-between gap-3 mb-3">
              <div>
                <h3 className="text-lg font-semibold" style={{ color: INK }}>Live delivery-person selfie</h3>
                <p className="text-xs mt-1" style={{ color: SLATE }}>
                  This must be taken now. Selecting a saved picture is not available.
                </p>
              </div>
              <button type="button" onClick={closeDeliverySelfieCamera} aria-label="Close live selfie camera">
                <X size={22} />
              </button>
            </div>
            <div className="relative overflow-hidden rounded-xl bg-black aspect-square">
              <video
                ref={deliverySelfieVideoRef}
                autoPlay
                muted
                playsInline
                className="w-full h-full object-cover -scale-x-100"
              />
              {!deliverySelfieCameraReady && (
                <div className="absolute inset-0 flex items-center justify-center text-sm text-white">Starting live camera…</div>
              )}
              <div className="absolute inset-[12%] rounded-full border-2 border-white/80 pointer-events-none" />
            </div>
            <p className="text-xs mt-3" style={{ color: SLATE }}>
              Center the delivery person’s full face inside the guide. Remove sunglasses, hats, and face coverings.
            </p>
            <button
              type="button"
              onClick={captureLiveDeliverySelfie}
              disabled={!deliverySelfieCameraReady || uploadingDeliverySelfieKey !== null}
              className="w-full mt-3 py-3 rounded-lg font-semibold disabled:opacity-50"
              style={{ backgroundColor: MARIGOLD, color: INK }}
            >
              {uploadingDeliverySelfieKey ? "Saving live selfie…" : "Take live selfie"}
            </button>
          </div>
        </div>
      )}
      {casualVerificationOpen && (
        <CasualSellerVerificationModal
          onClose={() => setCasualVerificationOpen(false)}
          authFetch={authFetch}
          showToast={showToast}
          onApproved={(result) => {
            setCasualSellerStatus((current) => ({
              ...(current || {}), status: result.status, limit: result.limit,
              application: { reference: result.reference, status: result.status, automatic_checks: result.checks },
            }));
            setSessionUserProfile((current) => current ? { ...current, casual_seller_status: result.status, casual_seller_limit: result.limit } : current);
          }}
        />
      )}
      {selectedCasualApplication && (
        <div className="fixed inset-0 z-[95] flex items-center justify-center p-4 overflow-y-auto" style={{ backgroundColor: "rgba(27,36,48,.78)" }} onClick={() => setSelectedCasualApplication(null)}>
          <div className="bg-white rounded-2xl max-w-5xl w-full p-5 my-6" onClick={(event) => event.stopPropagation()}>
            <div className="flex items-start justify-between gap-3 mb-4"><div><h3 className="text-xl" style={{ color: INK }}>{selectedCasualApplication.legal_name}</h3><p className="text-xs" style={{ color: SLATE }}>{selectedCasualApplication.reference} · @{selectedCasualApplication.username}</p></div><button onClick={() => setSelectedCasualApplication(null)}><X size={22} /></button></div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {Object.entries(casualEvidenceUrls).map(([key, url]) => <figure key={key}><img src={url} alt={key.replaceAll("_", " ")} className="w-full aspect-square object-contain rounded-lg border bg-black" /><figcaption className="text-xs mt-1 capitalize" style={{ color: SLATE }}>{key.replaceAll("_", " ")}</figcaption></figure>)}
            </div>
            <div className="mt-4 p-3 rounded-lg" style={{ backgroundColor: CANVAS }}><p className="text-sm font-medium mb-2" style={{ color: INK }}>Automatic checks</p><div className="flex flex-wrap gap-2">{Object.entries(selectedCasualApplication.automatic_checks || {}).map(([key, passed]) => <Tag key={key} color={passed ? SAGE : BERRY}>{key}: {passed ? "pass" : "fail"}</Tag>)}</div></div>
            {selectedCasualApplication.status === "approved" && <button onClick={async () => { const reason = window.prompt("Reason for suspension"); if (!reason) return; const response = await authFetch(`${BACKEND_URL}/admin/casual-seller-applications/${selectedCasualApplication.id}/suspend`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason }) }); if (response.ok) { showToast("Casual seller suspended and active listings paused"); setSelectedCasualApplication(null); fetchCasualSellerVerification(); } else showToast("Couldn't suspend this seller"); }} className="mt-4 px-4 py-2 rounded-lg text-sm font-medium" style={{ backgroundColor: BERRY, color: "white" }}>Suspend casual seller</button>}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Stallyard() {
  const currentPath = typeof window !== "undefined" ? window.location.pathname.replace(/\/+$/, "") || "/" : "/";
  const driverRoute = typeof window !== "undefined"
    ? window.location.pathname.match(/^\/driver\/delivery\/([A-Za-z0-9_-]{30,120})\/?$/)
    : null;

  if (driverRoute) {
    return (
      <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Opening secure delivery…</div>}>
        <DriverDelivery accessToken={driverRoute[1]} />
      </Suspense>
    );
  }

  if (currentPath === "/driver/dashboard") {
    return <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Opening Driver Dashboard…</div>}><DriverDashboard /></Suspense>;
  }

  if (currentPath === "/seller/driver-jobs") {
    return <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Opening delivery jobs…</div>}><SellerDriverJobs /></Suspense>;
  }

  return <MarketplaceStallyard />;
}


