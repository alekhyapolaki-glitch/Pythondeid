"""Static substitution lists used by the dictionary-based maskers."""

FIRST_NAMES = (
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth",
    "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen",
    "Christopher", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony", "Sandra", "Mark", "Margaret",
    "Donald", "Ashley", "Steven", "Kimberly", "Andrew", "Emily", "Paul", "Donna", "Joshua", "Michelle",
    "Kenneth", "Carol", "Kevin", "Amanda", "Brian", "Melissa", "George", "Deborah", "Timothy", "Stephanie",
    "Ronald", "Rebecca", "Jason", "Sharon", "Edward", "Laura", "Jeffrey", "Cynthia", "Ryan", "Dorothy",
    "Jacob", "Amy", "Gary", "Kathleen", "Nicholas", "Angela", "Eric", "Shirley", "Jonathan", "Brenda",
    "Stephen", "Emma", "Larry", "Anna", "Justin", "Pamela", "Scott", "Nicole", "Brandon", "Samantha",
    "Benjamin", "Katherine", "Samuel", "Christine", "Gregory", "Helen", "Alexander", "Debra", "Patrick", "Rachel",
    "Frank", "Carolyn", "Raymond", "Janet", "Jack", "Maria", "Dennis", "Olivia", "Jerry", "Heather",
    "Tyler", "Priya", "Aaron", "Mei", "Jose", "Fatima", "Adam", "Aisha", "Nathan", "Sofia",
    "Henry", "Yuki", "Zachary", "Ananya", "Douglas", "Chloe", "Peter", "Grace", "Kyle", "Leah",
)

LAST_NAMES = (
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
    "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
    "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
    "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper",
    "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
    "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez",
    "Reddy", "Chen", "Wang", "Singh", "Kumar", "Tanaka", "Silva", "Novak", "Okafor", "Larsen",
)

STREET_NAMES = (
    "Maple", "Oak", "Pine", "Cedar", "Elm", "Willow", "Birch", "Spruce", "Chestnut", "Walnut",
    "Lake", "Hill", "River", "Park", "Meadow", "Forest", "Sunset", "Highland", "Valley", "Spring",
    "Washington", "Lincoln", "Jefferson", "Madison", "Franklin", "Jackson", "Adams", "Monroe", "Main", "Church",
    "Mill", "Market", "Union", "Center", "Bridge", "Harbor", "Prospect", "Ridge", "Summit", "Grove",
)

STREET_SUFFIXES = ("St", "Ave", "Rd", "Blvd", "Ln", "Dr", "Ct", "Way", "Pl", "Ter")

CITIES = (
    "Springfield", "Riverton", "Fairview", "Greenville", "Franklin", "Clinton", "Georgetown", "Salem",
    "Madison", "Arlington", "Ashland", "Bristol", "Dover", "Oxford", "Milton", "Newport", "Burlington",
    "Manchester", "Lexington", "Hudson", "Kingston", "Marion", "Jackson", "Auburn", "Dayton", "Lebanon",
    "Clayton", "Winchester", "Chester", "Mount Vernon", "Oakland", "Centerville", "Lakewood", "Brookfield",
)

# ---------------------------------------------------------------------------
# Business / account names
# ---------------------------------------------------------------------------
# Distinctive words that replace the identifying part of a business name.
COMPANY_WORDS = (
    "Maple", "Summit", "Harbor", "Ridge", "Cedar", "Lakeside", "Northgate", "Silver", "Oakmont", "Riverbend",
    "Pinecrest", "Bluewater", "Granite", "Meadow", "Highland", "Westfield", "Eastwood", "Brookside", "Stonebridge",
    "Sterling", "Crescent", "Evergreen", "Fairway", "Golden", "Ironwood", "Juniper", "Keystone", "Liberty",
    "Magnolia", "Northstar", "Orchard", "Prairie", "Quarry", "Redwood", "Sagebrush", "Timber", "Unity", "Valley",
    "Willow", "Aspen", "Beacon", "Canyon", "Delta", "Echo", "Falcon", "Glacier", "Horizon", "Island", "Jasper",
    "Kingsley", "Lantern", "Mesa", "Nimbus", "Oasis", "Pioneer", "Quail", "Rockport", "Sequoia", "Trident",
    "Upland", "Vista", "Wexford", "Yardley", "Zenith", "Arbor", "Birchwood", "Cobalt", "Driftwood", "Elmhurst",
    "Foxglove", "Greystone", "Hawthorne", "Ivory", "Larkspur", "Millstone", "Newbury", "Osprey", "Parkview",
    "Rosewood", "Shoreline", "Tamarack", "Vantage", "Whitestone", "Bayside", "Clearwater", "Hillcrest", "Lakemont",
)

# Legal-form suffixes and generic industry words: not identifying, kept as they are
# (keep_industry_words: true) so masked names still read like the same kind of business.
BUSINESS_SUFFIXES = {
    "INC", "INCORPORATED", "LLC", "L.L.C", "LLP", "LP", "L.P", "LTD", "LIMITED", "CORP", "CORPORATION", "CO",
    "COMPANY", "PLLC", "PC", "P.C", "PA", "P.A", "SC", "S.C", "NA", "N.A", "PLC", "GMBH", "SA", "NV", "BV", "AG",
}
INDUSTRY_WORDS = {
    "ASSOC", "ASSOCS", "ASSOCIATES", "ASSOCIATION", "HOLDINGS", "HOLDING", "GROUP", "PARTNERS", "PARTNERSHIP",
    "BANK", "BANCORP", "FINANCIAL", "CAPITAL", "INVESTMENTS", "INVESTMENT", "FUND", "FUNDS", "EQUITY", "VENTURES",
    "DEVELOPMENT", "PROPERTIES", "PROPERTY", "REALTY", "REAL", "ESTATES", "MANAGEMENT", "MGMT", "ENTERPRISES",
    "ENTERPRISE", "INDUSTRIES", "SERVICES", "SERVICE", "SOLUTIONS", "SYSTEMS", "TECHNOLOGIES", "TECHNOLOGY", "TECH",
    "INTERNATIONAL", "INTL", "NATIONAL", "AMERICA", "AMERICAN", "GLOBAL", "CONSTRUCTION", "CONTRACTORS",
    "CONTRACTING", "BUILDERS", "HOMES", "ROOFING", "PLUMBING", "ELECTRIC", "ELECTRICAL", "LANDSCAPING", "MEDICAL",
    "DENTAL", "DENTISTRY", "PERIODONTICS", "ORTHODONTICS", "IMPLANT", "IMPLANTS", "CLINIC", "HEALTH", "HEALTHCARE",
    "CARE", "PHARMACY", "HOSPITAL", "LAW", "LEGAL", "FIRM", "OFFICE", "OFFICES", "ACCOUNTING", "CONSULTING",
    "CONSULTANTS", "INSURANCE", "AGENCY", "MOTORS", "AUTO", "AUTOMOTIVE", "TRANSPORT", "TRUCKING", "LOGISTICS",
    "RESTAURANT", "CAFE", "FOODS", "FOOD", "FARMS", "FARM", "MARKET", "STORE", "SHOP", "SUPPLY", "SUPPLIES",
    "DISTRIBUTION", "DISTRIBUTORS", "MANUFACTURING", "MFG", "PRODUCTS", "MEDIA", "MARKETING", "DESIGN", "STUDIO",
    "CHURCH", "MINISTRIES", "SCHOOL", "ACADEMY", "UNIVERSITY", "COLLEGE", "FOUNDATION", "CLUB", "CENTER",
    "CENTRE", "SOCIETY", "COUNCIL", "DISTRICT", "VILLAGE", "CITY", "COUNTY", "TOWNSHIP", "PARK", "CONDOMINIUM",
    "CONDO", "HOA", "APARTMENTS", "PLAZA", "TOWER", "HOTEL", "INN", "SALON", "SPA", "FITNESS", "VETERINARY",
}
# Words that mark a person-held account (trusts, estates, custodial accounts):
# the identifying words are replaced with person names instead of company words.
PERSONAL_ENTITY_WORDS = {
    "TRUST", "TRUSTEE", "TTEE", "TR", "ESTATE", "REVOCABLE", "IRREVOCABLE", "LIVING", "FAMILY", "IRA", "ROTH",
    "CUSTODIAN", "CUST", "FBO", "UTMA", "UGMA", "DECEASED", "DECD", "POA", "GUARDIAN", "MINOR", "DBA",
}
CONNECTOR_WORDS = {"&", "AND", "OF", "THE", "FOR", "AT", "ON", "IN", "+", "-", "/", "A/K/A", "AKA", "C/O"}
